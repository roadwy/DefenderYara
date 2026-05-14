
rule Trojan_Win64_ClipBanker_NC_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 89 08 48 8b 8c 24 b8 00 00 00 48 89 48 08 48 c7 40 10 00 00 00 00 48 c7 40 18 3f 00 0f 00 48 8b 8c 24 b0 00 00 00 48 89 48 20 48 8b 0d 2b bb 0a 00 48 89 c3 bf 05 00 00 00 48 89 c8 48 89 f9 } //2
		$a_01_1 = {48 8b 8c 24 c0 00 00 00 48 8b 11 48 89 10 48 8b 94 24 a8 00 00 00 48 89 50 08 48 c7 40 10 00 00 00 00 48 c7 40 18 01 00 00 00 48 8b 94 24 a0 00 00 00 48 89 50 20 48 8b 54 24 38 48 c1 e2 03 48 89 50 28 48 8b 15 a4 ba 0a 00 } //1
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}