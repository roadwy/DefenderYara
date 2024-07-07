
rule Trojan_Win32_ClipBanker_CBV_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.CBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {76 68 73 70 6f 73 69 6f 6e 2e 78 79 7a } //1 vhsposion.xyz
		$a_01_1 = {31 34 36 2e 31 39 2e 32 31 33 2e 32 34 38 } //1 146.19.213.248
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {4e 65 77 42 6f 74 3a } //1 NewBot:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}