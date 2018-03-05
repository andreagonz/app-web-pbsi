#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import re
import optparse
import requests
import configparser
from lxml import html
from requests.exceptions import ConnectionError
import itertools
from urlparse import urljoin
from urlparse import urlparse
import esprima
import urllib3

'''
Plan de Becarios en Seguridad Informática
Seguridad en Aplicaciones Web

Proyecto:
    Herramienta para de inspección a peticiones asíncronas HTTP

Equipo:
    Andrea Itzel González Vargas
    Pedro Ángel Valle Juárez
'''

class VisitorAjax(esprima.NodeVisitor):

    def __init__(self, lst):
        self.lst = lst
        self.url = ""
        super(VisitorAjax, self).__init__()
        
    def visit_CallExpression(self, node):
        ob = node.callee.object.name if node.callee.object else ''
        prop = node.callee.property.name if node.callee.property else ''
        if prop == 'ajax' and (ob == 'jQuery' or ob == '$'):
            self.lst.append((self.url, node))
        self.generic_visit(node)

class VisitorData(esprima.NodeVisitor):

    def __init__(self, data):
        self.data = data
        self.resultado = None
        super(VisitorAjax, self).__init__()
        
    def visit_CallExpression(self, node):
        ob = node.callee.object.name if node.callee.object else ''
        prop = node.callee.property.name if node.callee.property else ''
        if prop == 'ajax' and (ob == 'jQuery' or ob == '$'):
            self.lst.append((self.url, node))
        self.generic_visit(node)

def opciones():
    """
    Regresa un objeto que permite leer argumentos ingresados al ejecutar el programa.
    Regresa:
        optparse.OptionParser - Objeto analizador de argumentos
    """
    parser = optparse.OptionParser()
    parser.add_option('-c','--config', dest='config', default=None, help='Archivo de configuracion a ser utilizado.')
    parser.add_option('-a','--archivo', dest='archivo', default=False, action='store_true', help='Bandera que de ser usada, indica que la entrada del programa es un archivo.')
    return parser.parse_args()

def error(msg, exit=False):
    """
    Imprime msg en la salida de errores, termina el programa si se le indica.
    Recibe:
        msg (str) - Mensaje a imprimir
        exit (bool) - Se termina el programa syss es True
    Regresa:
        None
    """
    sys.stderr.write('Error:\t%s\n' % msg)
    if exit:
        sys.exit(1)

def obten_src(url, src):
    """
    Crea un url a partir de un url base y un recurso.
    Recibe:
        url (string) - URL base
        src (string) - Recurso, si es un URL, se regresa intacto
    Regresa:
        string - Un URL
    """
    urlp = urlparse(src)
    if len(urlp.netloc) == 0:
        return urljoin(url, src)
    return src

def peticion_ajax(t, sesion, agente, cookie, mostrar_respuesta, mostrar_funciones_asincronas):
    """
    Hace una petición usando una tupla de la forma (url, ajax), donde url
    es el recurso de donde se extrajo la función de ajax y ajax es la definición
    de la función que permite realizar peticiones asíncronas.    
    Recibe:
        t (tuple) - Tupla de la forma (string, esprima.Node)
    """
    url = t[0]
    ajax = t[1]
    metodo = 'GET'
    data = None
    contentType = 'application/x-www-form-urlencoded; charset=UTF-8'
    for prop in ajax.arguments[0].properties:
        if prop.key.name == 'type' or prop.key.name == 'method':
            metodo = prop.value.value if prop.value.type == "Literal" else metodo
        elif prop.key.name == 'url':
            url = obten_src(url, prop.value.value) if prop.value.type == "Literal" else url
        elif prop.key.name == 'contentType':
            contentType = prop.value.value if prop.value.type == "Literal" else contentType
        elif prop.key.name == 'data':
            data = prop.value.value if prop.value.type == "Literal" else None
            if data is None:
                data = prop.value
    print "\n------------------------------\n"
    print "Recurso: %s" % url
    if mostrar_funciones_asincronas:
        print "Funcion:"
        print ajax

    print metodo
    print contentType
    # print data if not data is None else ''
    if mostrar_respuesta:
        pass
    
def obten_ajax(lst):
    """
    A partir de una lista de tuplas de la forma (url, javascript), regresa una
    lista de tuplas de la forma (url, ajax).
    Recibe:
        lst (list) - Lista de tuplas de la forma (string, string)
    Regresa:
        list - Lista de tuplas de la forma (string, esprima.Node)
    """
    ajax = []
    visitor = VisitorAjax(ajax)
    for js in lst:
        if not js[1] is None:
            try:
                tree = esprima.parseScript(js[1], delegate=visitor)
            except Exception as e:
                error(str(e))
                continue
            visitor.url = js[0]
            visitor.visit(tree)
    return ajax

def obten_js(url, contenido, sesion, agente, cookie):
    """
    Regresa un arreglo con el texto de los scripts encontrados en el contenido.
    Recibe:
        contenido (str) - Recurso que será inspeccionado en busca de scripts.
        sesion (requests.session) - Sesión a utilizar
        agente (str) - Agente de usuario a utilizar
        cookie (str) - Cookie a ser utilizada.
    """
    tree = html.fromstring(contenido)
    return [(obten_src(url, x.get('src')),
             hacer_peticion(obten_src(url, x.get('src')), sesion, agente, cookie).text)
            if x.get('src') else (url, x.text) for x in tree.xpath("//script")]

def genera_url(uri):
    """
    Regresa el URL a partir del URI ingresado
    Recibe:
        uri (str) - URI a ser convertido a URL
    Regresa:
        str - URL generada
    """
    if not re.match('^https?://', uri):
        return 'http://%s' % (uri)
    return uri

def obten_sesion(proxy=None):
    """
    Regresa una sesión para realizar peticiones.
    Recibe:
        proxy (bool) - De ser True se crea una sesión que usa un proxy
    Regresa:
        sesión
    """
    sesion = requests
    if not proxy is None:
        sesion = requests.session()
        proxy_http = proxy
        proxy_https = proxy
        if not re.match('.*://.*', proxy):
            proxy = re.match(r"(https?://)?(.+)", proxy).group(2)
            proxy_http = 'http://%s' % proxy
            proxy_https = 'https://%s' % proxy
        sesion.proxies = {'http': proxy_http, 'https': proxy_https}
    return sesion

def hacer_peticion(url, sesion, agente=None, cookie=None, contentType=None, data=None):
    """
    Hace una petición al servidor.
    Recibe:
        url (str) - URL a la cuál se hace la petición
        sesion (requests.session) - Sesión a utilizar
        agente (str) - Agente de usuario a utilizar
        cookie (str) - Cookie a ser utilizada.
    Regresa:
        requests.models.Response - Respuesta a la petición
    """
    try:
        headers = {}
        if agente is not None:
            headers['User-Agent'] = agente
        if cookie is not None:
            headers['Cookie'] = cookie
        if contentType is not None:
            headers['Content-Type'] = contentType
        return sesion.get(url, headers=headers, verify=False)
    except ConnectionError as e:
        error('Error en la conexion: ' + str(e), True)
    return None

def leer_configuracion(archivo):
    """
    Lee el archivo de configuración y regresa un diccionario con los valores que éste indica.
    Recibe:
        archivo (str) - Nombre del archivo de configuración
    Regresa:
        dict - Diccionario con los valores de los parámetros
    """
    res = {}
    try:
        config = configparser.ConfigParser()
        config.read(archivo)
        res = config['CONFIGURACION']
    except:
        error("Hubo un problema al leer el archivo de configuración", True)
    return res

if __name__ == '__main__':
    # try:
    urllib3.disable_warnings()
    ops, args = opciones()
    if len(args) < 1:
        error("Uso: python proyecto.py <uri|archivo> [-a] [-c archivo.conf]", True)
    config = None if ops.config is None else leer_configuracion(ops.config)
    proxy = None
    agente = None
    cookie = None
    mostrar_respuesta = None
    mostrar_funciones_asincronas = False
    if not config is None:
        proxy = config.get('proxy', None)
        agente = config.get('user_agent', None)
        cookie = config.get('cookie', None)
        mostrar_respuesta = config.get('mostrar_respuesta', None)
        mostrar_funciones_asincronas = config.getboolean('mostrar_funciones_asincronas', fallback=False)
        print "Configuraciones:"
        print "	Proxy: %s" % ('Ninguno' if proxy is None else proxy)
        print "	Agente de usuario: %s" % ('Ninguno' if agente is None else agente)
        print "	Cookie: %s" % ('Ninguno' if cookie is None else cookie)
        print "	Mostrar respuesta: %s" % ('Ninguna' if mostrar_respuesta is None else mostrar_respuesta)
        print "	Mostrar funciones asíncronas: %s" % str(mostrar_funciones_asincronas)
    sesion = obten_sesion(proxy)
    url = genera_url(args[0])
    peticion = hacer_peticion(url, sesion, agente, cookie)
    ajax = obten_ajax(obten_js(url, peticion.content, sesion, agente, cookie))
    for x in ajax:
        peticion_ajax(x, sesion, agente, cookie, mostrar_respuesta, mostrar_funciones_asincronas)

    # except Exception as e:
        # error('Ocurrió un error inesperado')
        # error(e, True)
