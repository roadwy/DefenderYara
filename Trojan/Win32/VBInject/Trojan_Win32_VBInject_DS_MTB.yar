
rule Trojan_Win32_VBInject_DS_MTB{
	meta:
		description = "Trojan:Win32/VBInject.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {ff 34 08 5b 66 0f 6e d3 90 02 20 e8 90 02 04 f6 90 02 20 66 0f 7e 14 08 90 02 10 83 e9 fc 81 f9 90 01 04 75 90 01 01 f6 90 02 10 c3 f6 90 02 10 66 0f ef d1 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}