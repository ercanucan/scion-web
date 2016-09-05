
SCION_WELCOME_ASCII = ["#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>",  # noqa
                      "#>>>>>>>>===>>>>>>>>>>>>====>>>>>>>>>=  =>>>>>>>>>====>>>>>>>>>>>>>>>>>>>>>>>>>>>",  # noqa
                      "#>>>>=   ...  (>>>>>=   ....    >>>>>> ./>>>>>=   ....    >>>>>     >>>>>>)  >>>>",  # noqa
                      "#>>>>  (>>>>>>>>>>>   >>>>>>>>...>>>>>  (>>>>  .>>>>>>>>   =>>>      >>>>>)  >>>>",  # noqa
                      "#>>>>   =>>>>>>>>>   >>>>>>>>>>>>>>>>)  (>>>   >>>>>>>>>>   >>>   >\  =>>>)  >>>>",  # noqa
                      "#>>>>>>     =>>>>>  (>>>>>>>>>>>>>>>>====>>>  (>>>>>>>>>>>  >>>   >>\  (>>)  >>>>",  # noqa
                      "#>>>>>>>>>>.   =>>  (>>>>>>>>>>>>>>>>....>>>  (>>>>>>>>>>   >>>   >>>>  (>)  >>>>",  # noqa
                      "#>>>>>>>>>>>>  (>>   =>>>>>>>>>==>>>>    >>>   >>>>>>>>>=  (>>>   >>>>>   )  >>>>",  # noqa
                      "#>>>===>>>>>=  />>>   =>>>>>>=  />>>>=====>>>   =>>>>>>=  />>>>   >>>>>>     >>>>",  # noqa
                      "#>>>>.       />>>>>>><       .<>>>>>)    (>>>>>.       .<>>>>>>   >>>>>>>\   >>>>",  # noqa
                      "#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"]  # noqa

CLI_CONFIG = ['--zoom', '1.0', '--geometry', '180x24+150+150']

TMUX_CONFIG = ['set-option', 'status', 'off', ';',
               'set-option', 'set-titles', 'on', ';',
               'set-option', 'set-titles-string', 'SCION deployment', ';'
               ]

HELP_MESSAGE = ['send-key', 'Enter', ';',
                'send-key', '#Welcome to the SCION deployment framework', ';',
                'send-key', 'Enter', ';',
                'send-key', '#It uses Ansible playbooks to provide '
                            'a simple & efficient deployment procedure', ';',
                'send-key', 'Enter', ';',
                'send-key', 'Enter', ';'
                ]

SHOW_PWD = ['send-key', 'pwd', ';',
            'send-key', 'Enter', ';'
            ]

default_scion_deploy_dir = '~/scion-deploy'

SET_PWD = ['send-key', 'cd ' + default_scion_deploy_dir, ';',
           'send-key', 'Enter', ';'
           ]

SHOW_WELCOME = ['send-key', 'Enter', ';',
                'send-key', SCION_WELCOME_ASCII[0], ';',
                'send-key', 'Enter', ';',
                'send-key', SCION_WELCOME_ASCII[1], ';',
                'send-key', 'Enter', ';',
                'send-key', SCION_WELCOME_ASCII[2], ';',
                'send-key', 'Enter', ';',
                'send-key', SCION_WELCOME_ASCII[3], ';',
                'send-key', 'Enter', ';',
                'send-key', SCION_WELCOME_ASCII[4], ';',
                'send-key', 'Enter', ';',
                'send-key', SCION_WELCOME_ASCII[5], ';',
                'send-key', 'Enter', ';',
                'send-key', SCION_WELCOME_ASCII[6], ';',
                'send-key', 'Enter', ';',
                'send-key', SCION_WELCOME_ASCII[7], ';',
                'send-key', 'Enter', ';',
                'send-key', SCION_WELCOME_ASCII[8], ';',
                'send-key', 'Enter', ';',
                'send-key', SCION_WELCOME_ASCII[9], ';',
                'send-key', 'Enter', ';',
                'send-key', SCION_WELCOME_ASCII[10], ';',
                'send-key', 'Enter', ';'
                ]

default_playbook = 'deploy.yml'

default_hostfile = '~/scion/sub/web/gen/ISD1/host.1-1'

SHOW_ANSIBLE_COMMAND = ['send-key', 'ansible-playbook ' + default_playbook +
                                    ' -i ' + default_hostfile +
                                    ' --verbose']
