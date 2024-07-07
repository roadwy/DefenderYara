
rule Trojan_Win32_Vidar_BC_MTB{
	meta:
		description = "Trojan:Win32/Vidar.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 0c 51 03 de ff d7 8b c8 33 d2 8b c6 f7 f1 8b 45 0c 68 90 01 03 00 8a 0c 02 8b 55 f8 32 0c 1a 88 0b ff d7 68 90 01 03 00 ff d7 68 90 01 03 00 ff d7 8b 5d fc 46 3b 75 10 72 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}