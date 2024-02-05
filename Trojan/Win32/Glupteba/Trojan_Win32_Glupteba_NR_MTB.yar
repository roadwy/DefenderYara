
rule Trojan_Win32_Glupteba_NR_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c6 c1 e8 05 03 90 02 05 03 90 02 05 03 90 02 03 33 90 02 03 33 90 02 03 89 90 02 03 89 90 02 05 89 90 02 05 8b 90 02 05 29 90 02 03 8b 90 02 05 29 90 02 03 ff 90 02 05 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}