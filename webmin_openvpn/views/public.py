from pyramid.view import view_config
from pyramid.httpexceptions import HTTPFound


@view_config(route_name='home')
def home_redirect_view(request):
    """
    Redirect root URL directly to admin dashboard.
    """
    return HTTPFound(location=request.route_url('admin_dashboard'))


def includeme(config):
    config.add_route('home', '/')
    config.scan(__name__)
