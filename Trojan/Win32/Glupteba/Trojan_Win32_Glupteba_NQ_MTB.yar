
rule Trojan_Win32_Glupteba_NQ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 d1 31 55 90 01 01 8b 90 02 03 8d 90 02 05 e8 90 02 04 81 3d 90 02 08 75 90 00 } //01 00 
		$a_02_1 = {33 45 70 83 25 90 02 08 8b c8 89 45 90 02 01 8d 90 02 05 e8 90 02 04 81 90 02 05 ff 90 02 05 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}