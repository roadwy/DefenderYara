
rule Trojan_Win32_DiscoveryTechnique_ZPA{
	meta:
		description = "Trojan:Win32/DiscoveryTechnique.ZPA,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6e 00 65 00 74 00 73 00 68 00 } //1 netsh
		$a_00_1 = {77 00 6c 00 61 00 6e 00 } //1 wlan
		$a_00_2 = {73 00 68 00 6f 00 77 00 20 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 20 00 2a 00 20 00 6b 00 65 00 79 00 3d 00 63 00 6c 00 65 00 61 00 72 00 } //1 show profile * key=clear
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}