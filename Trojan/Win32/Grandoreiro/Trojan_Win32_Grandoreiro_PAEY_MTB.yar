
rule Trojan_Win32_Grandoreiro_PAEY_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.PAEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 00 6f 00 6f 00 47 00 6c 00 65 00 20 00 33 00 2e 00 32 00 } //2 GooGle 3.2
		$a_01_1 = {8b 04 24 57 89 e7 81 c7 04 00 00 00 81 c7 04 00 00 00 33 3c 24 31 3c 24 33 3c 24 8b 24 24 e9 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}