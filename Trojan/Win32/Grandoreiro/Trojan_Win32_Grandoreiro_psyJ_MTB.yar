
rule Trojan_Win32_Grandoreiro_psyJ_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.psyJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 04 85 ce 75 26 e8 94 ff ff ff 8b c8 3b cf 75 07 b9 4f e6 40 bb eb 0e 85 ce 75 0a 0d 11 47 00 00 c1 e0 10 0b c8 89 0d 18 7c 40 00 f7 d1 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}