
rule Trojan_AndroidOS_Bankbot_E_MTB{
	meta:
		description = "Trojan:AndroidOS/Bankbot.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 65 72 76 69 63 65 2e 77 65 62 76 69 65 77 2e 6b 69 73 7a 77 65 62 } //1 service.webview.kiszweb
		$a_00_1 = {62 72 61 7a 69 6c 69 61 6e 6b 69 6e 67 73 2e 64 64 6e 73 } //1 braziliankings.ddns
		$a_00_2 = {2f 6d 6f 62 69 6c 65 43 6f 6e 66 69 67 2e 70 68 70 } //1 /mobileConfig.php
		$a_00_3 = {63 6f 6d 2e 76 74 6d 2e 75 6e 69 6e 73 74 61 6c 6c } //1 com.vtm.uninstall
		$a_00_4 = {73 74 61 72 74 54 72 61 63 6b 69 6e 67 } //1 startTracking
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}