
rule TrojanSpy_Win32_Bancos_OV{
	meta:
		description = "TrojanSpy:Win32/Bancos.OV,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 65 6e 68 61 20 64 6f 20 43 61 72 74 e3 6f 3a } //1
		$a_00_1 = {3a 2a 3a 45 6e 61 62 6c 65 64 3a 62 62 66 75 63 6b 00 } //1 ⨺䔺慮汢摥戺晢捵k
		$a_00_2 = {42 61 6e 63 6f 20 64 6f 20 42 72 61 73 69 6c 20 49 6e 74 65 72 6e 65 74 20 42 61 6e 6b 69 6e 67 00 } //1
		$a_00_3 = {72 65 67 69 73 74 72 61 72 67 62 66 75 63 6b } //1 registrargbfuck
		$a_00_4 = {66 75 63 6b 74 68 65 73 79 73 74 65 6d } //1 fuckthesystem
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}