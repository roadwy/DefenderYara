
rule Trojan_Linux_Mirai_YB_MTB{
	meta:
		description = "Trojan:Linux/Mirai.YB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {64 6f 74 68 65 6e 65 65 64 66 75 6c 6c 2e 78 79 7a } //4 dotheneedfull.xyz
		$a_00_1 = {74 6d 70 2f 66 65 74 63 68 } //1 tmp/fetch
		$a_00_2 = {61 63 74 69 6f 6e 48 61 6e 64 6c 65 72 2f 61 6a 61 78 5f 6e 65 74 77 6f 72 6b 5f 64 69 61 67 6e 6f 73 74 69 63 5f 74 6f 6f 6c 73 2e 70 68 70 } //1 actionHandler/ajax_network_diagnostic_tools.php
		$a_00_3 = {73 6d 61 72 74 64 6f 6d 75 73 70 61 64 2f 6d 6f 64 75 6c 65 73 2f 72 65 70 6f 72 74 69 6e 67 2f 74 72 61 63 6b 5f 69 6d 70 6f 72 74 5f 65 78 70 6f 72 74 2e 70 68 70 20 } //1 smartdomuspad/modules/reporting/track_import_export.php 
		$a_00_4 = {76 69 65 77 2f 49 50 56 36 2f 69 70 76 36 6e 65 74 77 6f 72 6b 74 6f 6f 6c 2f 74 72 61 63 65 72 6f 75 74 65 2f 70 69 6e 67 2e 70 68 70 } //1 view/IPV6/ipv6networktool/traceroute/ping.php
	condition:
		((#a_00_0  & 1)*4+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}