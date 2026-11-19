# SPDX-License-Identifier: LGPL-2.1-or-later

xsltproc = find_program('xsltproc', required : false)
if xsltproc.found()
        custom_target(
                'platformd-attestd.8',
                input : 'platformd-attestd.xml',
                output : 'platformd-attestd.8',
                command : [
                        xsltproc, '--nonet',
                        '--stringparam', 'man.output.quietly', '1',
                        '--stringparam', 'man.authors.section.enabled', '0',
                        '-o', '@OUTPUT@',
                        'http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl',
                        '@INPUT@',
                ],
                install : true,
                install_dir : get_option('mandir') / 'man8',
        )
else
        warning('xsltproc not found; man pages will not be built.')
endif
