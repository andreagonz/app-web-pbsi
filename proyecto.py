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
import random

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
        if (prop == 'ajax' or prop == 'get' or prop == 'post') and (ob == 'jQuery' or ob == '$'):
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
    if src is None:
        return url
    src = re.match('^(//)?(.+)', src).group(2)
    urlp = urlparse(src)
    if len(urlp.netloc) == 0:
        return urljoin(url, src)
    return src

def imprime_peticion(peticion, body):
    """
    Imprime una petición HTTP.
    """
    if peticion is None:
        print 'Error en petición\n'
    else:
        b = "\n%s\n" % peticion.body if body and not peticion.body is None else ''
        urn = re.match('(https?://)?(.+)', peticion.url).group(2)
        print '%s %s HTTP/1.1\n%s\n%s\n' % (peticion.method, urn,
                                          '\n'.join('%s: %s' % (k, v)
                                                    for k, v in peticion.headers.items()), b)

def imprime_respuesta(respuesta, body):
    """
    Imprime la respuesta HTTP del servidor.
    """
    print "Respuesta:"
    if respuesta is None:
        print 'Error en respuesta\n'
    else:
        b = respuesta.text if body and not respuesta.text is None else ''
        urn = re.match('(https?://)?(.+)', respuesta.url).group(2)
        print 'HTTP/1.1 %s %s\n%s\n%s' % (respuesta.status_code,
                                          requests.status_codes._codes[respuesta.status_code][0],
                                          '\n'.join('%s: %s' % (k, v)
                                                    for k, v in respuesta.headers.items()), b)

def numachar(n):
    """
    Mapea el entero n a un carácter en base64.
    """
    if n == 62:
        return '+';
    if n == 63:
        return '/';
    if n < 26:
        return chr(n + ord('A'))
    if n < 52:
        return chr(n - 26 + ord('a'))
    else:
        return chr(n - 52 + ord('0'))

def sig_char():
    """
    Regresa un carácter en base64.
    """
    return numachar(random.randint(0, 63))
    
def genera_str_aleatoria(n, m):
    """
    Genera una cadena aleatoria de longitud n a m.
    """
    s = []
    for x in range(random.randint(n, m)):
        s.append(sig_char())
    return ''.join(s)

def regresa_kv(p):
    """
    Regresa el nombre una llave y su valor en un ObjectExpression
    """
    k = None
    v = None
    k = p.key.name if p.key.type == 'Identifier' else k
    k = p.key.value if p.key.type == 'Literal' else k
    k = genera_str_aleatoria(3, 10) if k is None else k
    v = p.value.value if p.value.type == 'Literal' else v
    v = genera_str_aleatoria(3, 10) if v is None else v
    return k,v
    
def obten_data(valor, metodo):
    """
    Obtiene los datos especificados en la sección data de la función
    asíncrona y los devuelve como cadena, como diccionario o nulos
    si no se sabe que datos recolectar.
    """
    data = valor.value if valor.type == "Literal" else None
    if metodo == 'POST' and not data is None:
        return data
    if metodo == 'GET' and not data is None:
        dicc = {}
        lst = re.findall('[^&]+=[^&]+', data)
        for l in lst:
            m = re.match('(.+)=(.+)', l)
            dicc[m.group(1).strip()] = m.group(2).strip()
        return dicc
    if valor.type == "ObjectExpression":
        if metodo == 'GET':
            dicc = {}
            for p in valor.properties:
                k, v = regresa_kv(p)
                dicc[k] = v
            return dicc
        elif metodo == 'POST':
            s = ''
            for p in valor.properties:
                k, v = regresa_kv(p)
                s += '%s=%s&' % (k, v)
            return s[:-1]
    return None

def genera_data(ct):
    """
    Genera datos aleatorios basándose en el Content-Type
    """
    if ct == 'text/plain':
        return genera_str_aleatoria(10, 20)
    elif ct == 'text/css':
        return 'body {\n color: %s; }' % genera_str_aleatoria(5, 8)
    elif ct == 'text/csv':
        return '%s,%s,%s' % (genera_str_aleatoria(5, 8), genera_str_aleatoria(5, 8), genera_str_aleatoria(5, 8))
    elif ct == 'text/html':
        return '<h1>%s</h1>' % genera_str_aleatoria(5, 8)
    elif ct == 'text/xml':
        return '<hola>%s</hola>' % genera_str_aleatoria(5, 8)
    elif re.match('(?:image|audio|video|application)/.+', ct):
        return genera_str_aleatoria(50, 200)
    return None

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
    tipo = ajax.callee.property.name
    metodo = 'POST' if tipo == 'post' else 'GET'
    data = None
    contentType = 'application/x-www-form-urlencoded; charset=UTF-8'    
    print "Recurso: %s" % url    
    if len(ajax.arguments) == 0:
        error("Función AJAX sin datos")
        return    
    if tipo == 'ajax':
        i = 0
        if len(ajax.arguments) == 2:
            i = 1
            url = genera_url(ajax.arguments[0].value)
        for prop in ajax.arguments[i].properties:
            if prop.key.name == 'type' or prop.key.name == 'method':
                metodo = prop.value.value if prop.value.type == "Literal" else metodo
            elif prop.key.name == 'url':
                url = genera_url(obten_src(url, prop.value.value)) if prop.value.type == "Literal" else genera_url(url)
            elif prop.key.name == 'contentType':
                contentType = prop.value.value if prop.value.type == "Literal" else contentType
            elif prop.key.name == 'data':
                data = obten_data(prop.value, metodo)
    else:
        url = genera_url(obten_src(url, ajax.arguments[0].value))
        for x in range(1, len(ajax.arguments)):
            if ajax.arguments[x].type == 'ObjectExpression' or ajax.arguments[x].type == 'Literal':
                data = obten_data(ajax.arguments[x], metodo)
    data = genera_data(contentType) if data is None and metodo == 'POST' else data
    if mostrar_funciones_asincronas:
        print "\nFuncion asíncrona:"
        print ajax
    peticion = hacer_peticion(url, sesion, agente, cookie, contentType, data, metodo)
    if not peticion is None:
        print '\nPetición realizada:'
        imprime_peticion(peticion.request, True)
        if mostrar_respuesta == "cabeceras":            
            imprime_respuesta(peticion, False)
        elif mostrar_respuesta == "completa":
            imprime_respuesta(peticion, True)
        else:
            print "Código de respuesta: %s\n" % peticion.status_code
    print "------------------------------\n"
    
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
    if not re.match('https?://', uri):
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

def hacer_peticion(url, sesion, agente=None, cookie=None, contentType=None, data=None, metodo='GET'):
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
        if contentType is not None and metodo == 'POST':
            headers['Content-Type'] = contentType
        if metodo == 'GET':
            return sesion.get(url, headers=headers, verify=False, params=data)
        elif metodo == 'POST':
            return sesion.post(url, headers=headers, verify=False, data=data)
    except ConnectionError as e:
        error('Error en la conexion: ' + str(e), False)
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
    ajax = None
    print "\n------------------------------\n"
    if ops.archivo:
        f = open(args[0])
        js = f.read()
        f.close()
        ajax = obten_ajax([(args[0], js)])
    else:
        peticion = hacer_peticion(url, sesion, agente, cookie)
        ajax = obten_ajax(obten_js(url, peticion.content, sesion, agente, cookie))
    for x in ajax:
        peticion_ajax(x, sesion, agente, cookie, mostrar_respuesta, mostrar_funciones_asincronas)
    # except Exception as e:
        # error('Ocurrió un error inesperado')
        # error(e, True)
