
rule Trojan_Win32_Neoreblamy_NG_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {b4 31 d7 43 28 50 6b 99 d6 6e 84 12 a2 fc b7 0c a4 30 04 a7 35 5e b8 77 35 } //2
		$a_01_1 = {55 32 cd d2 45 6b 3a 39 78 c0 35 17 2c 98 30 fb bf 81 7d e4 05 3c 00 } //1
		$a_01_2 = {33 ff 47 8b 4d 88 33 d2 8b 45 d4 3b c8 0f 9d c2 4a 75 03 8b 45 d0 8b 45 d8 ba 96 a7 00 00 8b 45 d8 33 c9 8b 45 ec 2b d0 8b 45 e8 3b c2 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}