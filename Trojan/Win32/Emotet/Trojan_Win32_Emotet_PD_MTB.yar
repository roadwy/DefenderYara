
rule Trojan_Win32_Emotet_PD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 16 8d 49 04 81 f2 90 01 04 8d 76 04 88 51 fc 8b c2 c1 e8 08 47 c1 ea 10 88 41 fd 88 51 fe c1 ea 08 88 51 ff 3b fb 72 90 00 } //1
		$a_03_1 = {8b 0e 8d 52 08 33 4d 90 01 01 8d 76 04 0f b6 c1 43 66 89 42 f8 8b c1 c1 e8 08 0f b6 c0 66 89 42 fa c1 e9 10 0f b6 c1 66 89 42 fc c1 e9 08 0f b6 c1 66 89 42 fe 3b df 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}