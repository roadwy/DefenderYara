
rule Trojan_Win64_Filisto_K_dha{
	meta:
		description = "Trojan:Win64/Filisto.K!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5c d4 00 00 [0-04] c7 81 60 d4 00 00 00 00 02 00 ?? ?? 68 d4 00 00 [0-07] [30 34 40] 28 01 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}