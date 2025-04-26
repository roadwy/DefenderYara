
rule Trojan_Win32_SentryTome_A_dha{
	meta:
		description = "Trojan:Win32/SentryTome.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {ee c6 44 24 ?? c1 [0-04] c6 44 24 ?? c4 [0-04] c6 44 24 ?? 87 [0-04] c6 44 24 ?? a9 [0-04] c6 44 24 ?? f0 } //1
		$a_02_1 = {fd c6 44 24 ?? 5b [0-04] c6 44 24 ?? 84 [0-04] c6 44 24 ?? 3a [0-04] c6 44 24 ?? 12 [0-04] c6 44 24 ?? d0 } //1
		$a_02_2 = {d0 c6 44 24 ?? cd [0-09] c6 44 24 ?? 58 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}