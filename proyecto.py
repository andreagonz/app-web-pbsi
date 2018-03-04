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

# Agentes de usuario más comunes.
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/604.3.5 (KHTML, like Gecko) Version/11.0.1 Safari/604.3.5",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0"
]

class MiVisitor(esprima.NodeVisitor):

    def __init__(self, lst):
        self.lst = lst
        self.url = ""
        super(MiVisitor, self).__init__()
        
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
    parser.add_option('-a','--agente-usuario', dest='agente', default=None, help='Agente de usuario a ser utilizado para las peticiones.')
    parser.add_option('-p','--proxy', dest='proxy', default=None, help='')
    parser.add_option('-u','--uri', dest='uri', default=None, help='URI del recurso a inspeccionar.')
    opts, args = parser.parse_args()
    return opts

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
    visitor = MiVisitor(ajax)
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

def hacer_peticion(url, sesion, agente, cookie):
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
        if agente is not None:
            headers = {'User-Agent': agente}
            return sesion.get(url, headers=headers, verify=False)
        return sesion.get(url, verify=False)
    except ConnectionError as e:
        error('Error en la conexion: ' + str(e), True)
    return None

if __name__ == '__main__':
    # try:
    urllib3.disable_warnings()
    ops = opciones()
    sesion = obten_sesion(getattr(ops, 'proxy', None))
    url = genera_url(ops.uri)
    peticion = hacer_peticion(url, sesion, None, "")
    ajax = obten_ajax(obten_js(url, peticion.content, sesion, None, ""))
    for x in ajax:
        print x
    # except Exception as e:
        # error('Ocurrió un error inesperado')
        # error(e, True)
