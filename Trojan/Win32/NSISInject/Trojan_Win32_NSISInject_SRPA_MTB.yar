
rule Trojan_Win32_NSISInject_SRPA_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.SRPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {0f be 11 81 f2 a6 00 00 00 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 0f be 11 83 c2 7a } //00 00 
	condition:
		any of ($a_*)
 
}