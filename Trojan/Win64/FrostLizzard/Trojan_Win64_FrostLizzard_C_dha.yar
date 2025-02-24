
rule Trojan_Win64_FrostLizzard_C_dha{
	meta:
		description = "Trojan:Win64/FrostLizzard.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 44 24 40 33 d2 48 8b 44 24 40 8b 48 ?? e8 4e fd ff ff 48 89 84 24 ?? 00 00 00 48 ?? 44 24 40 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}