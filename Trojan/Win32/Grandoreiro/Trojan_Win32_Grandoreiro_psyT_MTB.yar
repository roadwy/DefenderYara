
rule Trojan_Win32_Grandoreiro_psyT_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.psyT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 53 33 f6 3b c3 76 21 68 ff 00 00 00 6a 01 e8 2e 3b 00 00 50 53 e8 27 3b 00 00 83 c4 10 88 04 3e 8b 45 f0 46 3b f0 72 df } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}