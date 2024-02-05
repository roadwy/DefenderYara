
rule Trojan_Win32_Glupteba_NK_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c7 c1 e8 05 03 90 02 05 03 90 02 05 03 90 02 03 33 90 02 03 81 3d 90 02 08 89 90 02 03 90 18 90 02 0a 33 90 02 03 89 90 02 05 8b 90 02 05 29 90 02 03 81 90 02 0a ff 90 02 05 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}