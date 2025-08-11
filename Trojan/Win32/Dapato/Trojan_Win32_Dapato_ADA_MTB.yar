
rule Trojan_Win32_Dapato_ADA_MTB{
	meta:
		description = "Trojan:Win32/Dapato.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d3 03 55 c8 03 c2 8b 55 e4 03 d6 8b cf e8 ?? ?? ?? ?? 01 7d c8 6a 00 e8 ?? ?? ?? ?? 03 c7 01 c6 8b 45 d0 01 c6 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Dapato_ADA_MTB_2{
	meta:
		description = "Trojan:Win32/Dapato.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {be f8 93 8a 00 b8 38 93 8a 00 0f 45 f0 33 ff 80 3e 00 74 49 8b d6 8d 59 28 52 8d 4d d8 } //1
		$a_01_1 = {8b ec 51 8d 45 fc 50 68 40 9f 7c 00 68 00 00 00 80 ff 15 74 70 7c 00 f7 d8 1a c0 fe c0 8b e5 5d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}