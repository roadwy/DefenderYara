
rule Trojan_Win32_LummaC_BR_MTB{
	meta:
		description = "Trojan:Win32/LummaC.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 0f b7 08 03 4d fc 89 4d fc 8b 55 f8 0f b7 42 02 c1 e0 0b 33 45 fc 89 45 e8 8b 4d fc c1 e1 10 33 4d e8 89 4d fc 8b 55 f8 83 c2 04 89 55 f8 8b 45 fc c1 e8 0b 03 45 fc 89 45 fc eb } //4
		$a_01_1 = {03 4d fc 89 4d fc 8b 45 fc 8b e5 5d } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}