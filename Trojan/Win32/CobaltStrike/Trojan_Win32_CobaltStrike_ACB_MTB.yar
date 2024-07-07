
rule Trojan_Win32_CobaltStrike_ACB_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.ACB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 45 dc 43 72 79 70 c7 45 e0 74 44 65 63 c7 45 e4 72 79 70 74 c6 45 e8 00 ff d7 } //1
		$a_01_1 = {c7 45 ac 43 72 79 70 c7 45 b0 74 44 65 72 c7 45 b4 69 76 65 4b 66 c7 45 b8 65 79 c6 45 ba 00 ff d7 } //1
		$a_01_2 = {c7 45 94 76 00 61 00 c7 45 98 70 00 69 00 c7 45 9c 33 00 32 00 c7 45 a0 2e 00 64 00 c7 45 a4 6c 00 6c 00 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}