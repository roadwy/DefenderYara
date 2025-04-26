
rule Trojan_Win32_Grandoreiro_PAFD_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.PAFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 00 6c 00 70 00 20 00 4c 00 6f 00 70 00 65 00 72 00 } //2 Dlp Loper
		$a_01_1 = {2e 74 68 65 6d 69 64 61 } //2 .themida
		$a_01_2 = {31 00 39 00 2e 00 37 00 2e 00 34 00 36 00 37 00 34 00 2e 00 31 00 } //2 19.7.4674.1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}