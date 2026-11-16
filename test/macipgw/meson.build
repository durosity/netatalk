iptoa_test = executable(
    'iptoa_test',
    'test_iptoa.c',
    '../../contrib/macipgw/util.c',
    include_directories: root_includes,
    install: false,
)

test('macipgw IPv4 address formatting', iptoa_test)

lanident_test = executable(
    'lanident_test',
    'test_lanident.c',
    '../../contrib/macipgw/lan_ident.c',
    include_directories: root_includes,
    install: false,
)

test('macipgw LAN mode identity and MAC derivation', lanident_test)
