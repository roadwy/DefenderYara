
rule Trojan_Win32_Neoreblamy_AP_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec ff 75 18 68 1b 03 00 00 6a 01 ff 75 08 68 4c 28 00 00 ff 75 14 68 f2 28 00 00 ff 75 0c 68 e8 4a 00 00 ff 75 10 68 c9 38 00 00 6a 01 e8 ?? ?? 00 00 83 c4 30 5d c3 } //2
		$a_01_1 = {c7 85 7c ff ff ff 10 b9 13 17 c7 85 dc fb ff ff 5c 46 f2 0b c7 85 88 ea ff ff a9 51 03 ec c7 85 08 f4 ff ff 87 59 b0 91 } //2
		$a_01_2 = {67 62 49 54 4e 50 77 62 59 73 4d 6c 61 47 6c 44 57 6e 49 58 67 42 47 67 46 57 73 48 56 74 42 4e } //1 gbITNPwbYsMlaGlDWnIXgBGgFWsHVtBN
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}