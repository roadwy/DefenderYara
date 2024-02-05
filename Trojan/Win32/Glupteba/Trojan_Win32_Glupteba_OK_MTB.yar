
rule Trojan_Win32_Glupteba_OK_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b cf c1 e9 05 89 90 02 03 8b 90 02 03 01 90 02 03 8b 90 01 01 c1 e6 90 01 01 03 90 02 03 8d 90 02 02 33 90 01 01 81 90 02 09 c7 90 02 09 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}