
rule Trojan_Win32_Gozi_AM_MTB{
	meta:
		description = "Trojan:Win32/Gozi.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 f8 6c 00 00 00 89 45 c0 89 f0 01 f8 05 38 00 00 00 8b 7d c0 69 ff 6c 00 00 00 } //4
		$a_01_1 = {8b 45 e8 8b 4d f0 8a 14 01 8b 75 ec 88 14 06 05 01 00 00 00 8b 7d f4 39 f8 89 45 e8 75 e2 } //4
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4) >=8
 
}