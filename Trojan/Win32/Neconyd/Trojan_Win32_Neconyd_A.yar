
rule Trojan_Win32_Neconyd_A{
	meta:
		description = "Trojan:Win32/Neconyd.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6f 00 62 00 5e 00 72 00 65 00 76 00 3d 00 25 00 73 00 5e 00 6f 00 73 00 3d 00 25 00 73 00 } //1 job^rev=%s^os=%s
		$a_01_1 = {47 00 52 00 41 00 42 00 46 00 54 00 50 00 53 00 } //1 GRABFTPS
		$a_01_2 = {5e 00 73 00 69 00 74 00 65 00 3d 00 25 00 73 00 5e 00 73 00 65 00 61 00 72 00 63 00 68 00 65 00 73 00 3d 00 25 00 73 00 5e 00 63 00 6c 00 69 00 63 00 6b 00 73 00 } //1 ^site=%s^searches=%s^clicks
		$a_01_3 = {66 83 38 00 56 8b f1 8b c8 74 08 41 41 66 83 39 00 75 f8 0f b7 16 66 89 11 41 41 46 46 66 85 d2 75 f1 5e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win32_Neconyd_A_2{
	meta:
		description = "Trojan:Win32/Neconyd.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 c8 55 0f 00 57 ff 15 28 80 40 00 57 8b f0 8d 45 f8 50 68 40 42 0f 00 56 53 ff 15 1c 80 40 00 80 3d 54 92 40 00 00 b9 54 92 40 00 8b c1 74 06 40 80 38 00 75 fa 2b c1 50 e8 f0 fd ff ff 8d 9e c8 ac 00 00 bf 60 ae 0a 00 a1 8c e8 41 00 40 be ff 00 00 00 23 c6 a3 8c e8 41 00 ff 15 20 80 40 00 a1 8c e8 41 00 0f b6 80 98 ec 41 00 03 05 84 e6 41 00 68 84 03 00 00 23 c6 a3 84 e6 41 00 e8 4a 01 00 00 85 c0 59 74 07 50 e8 62 00 00 00 59 } //1
		$a_01_1 = {6f 30 65 5b 45 73 65 6f 66 20 5d 65 20 6a 6e 63 70 61 20 65 69 6f 77 6b 45 4f } //1 o0e[Eseof ]e jncpa eiowkEO
		$a_01_2 = {4c 4f 65 69 20 45 4e 75 71 } //1 LOei ENuq
		$a_01_3 = {69 6f 45 6f 65 20 4e 45 64 31 75 69 77 } //1 ioEoe NEd1uiw
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}