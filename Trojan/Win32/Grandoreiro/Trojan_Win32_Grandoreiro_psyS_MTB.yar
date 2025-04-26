
rule Trojan_Win32_Grandoreiro_psyS_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.psyS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 66 ad 03 c3 ab e2 f7 91 6a 04 68 00 10 00 00 68 60 ee a6 00 50 ff 93 14 11 00 00 85 c0 74 e9 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}