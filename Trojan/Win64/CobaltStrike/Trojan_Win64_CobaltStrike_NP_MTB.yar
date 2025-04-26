
rule Trojan_Win64_CobaltStrike_NP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5f 5a 53 74 31 31 5f 5f 61 64 64 72 65 73 73 6f 66 49 31 33 5f 53 54 41 52 54 55 50 49 4e 46 4f 41 45 50 54 5f 52 53 31 5f } //1 _ZSt11__addressofI13_STARTUPINFOAEPT_RS1_
		$a_01_1 = {5f 5a 31 31 52 75 6e 54 68 61 74 53 68 69 74 76 } //1 _Z11RunThatShitv
		$a_01_2 = {5f 5a 53 74 39 61 64 64 72 65 73 73 6f 66 49 31 33 5f 53 54 41 52 54 55 50 49 4e 46 4f 41 45 50 54 5f 52 53 31 5f } //1 _ZSt9addressofI13_STARTUPINFOAEPT_RS1_
		$a_01_3 = {53 68 65 6c 6c 63 6f 64 65 20 69 6e 6a 65 63 74 65 64 } //1 Shellcode injected
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}