
rule Trojan_Win32_Vidar_VE_MTB{
	meta:
		description = "Trojan:Win32/Vidar.VE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 33 d2 8b c3 f7 f1 8b 45 0c 56 8a 0c 02 8b 55 fc 8d 04 13 8b 55 08 32 0c 02 88 08 ff d7 56 ff d7 56 ff d7 56 ff d7 56 ff d7 56 ff d7 43 3b 5d 10 72 a7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}