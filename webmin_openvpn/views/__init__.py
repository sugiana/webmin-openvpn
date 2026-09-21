def includeme(config):
    """
    Include all view modules and routing configurations.
    """
    config.include('.auth')
    config.include('.admin')
    config.include('.public')
