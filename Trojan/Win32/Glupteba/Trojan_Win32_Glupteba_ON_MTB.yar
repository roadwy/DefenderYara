
rule Trojan_Win32_Glupteba_ON_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.ON!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 c7 05 90 02 08 c7 05 90 02 08 89 90 02 03 8b 90 02 03 01 90 02 03 81 3d 90 02 08 90 18 8b 90 02 03 33 90 02 03 33 90 02 03 8d 90 02 03 e8 90 02 04 81 3d 90 02 08 90 18 8d 90 02 03 e8 90 02 04 83 90 02 04 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}