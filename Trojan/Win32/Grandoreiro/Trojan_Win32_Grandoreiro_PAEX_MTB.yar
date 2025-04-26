
rule Trojan_Win32_Grandoreiro_PAEX_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.PAEX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 00 6f 00 6f 00 47 00 6c 00 65 00 20 00 33 00 2e 00 32 00 } //2 GooGle 3.2
		$a_01_1 = {74 68 65 6d 69 64 61 } //2 themida
		$a_01_2 = {31 00 39 00 2e 00 37 00 2e 00 34 00 36 00 37 00 34 00 2e 00 31 00 31 00 } //2 19.7.4674.11
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}