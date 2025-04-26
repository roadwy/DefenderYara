
rule Trojan_Win32_CobaltStrike_PU_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.PU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 aa 26 00 00 31 d2 [0-0a] c7 44 24 ?? 5c 00 00 00 c7 44 24 ?? 65 00 00 00 c7 44 24 ?? 70 00 00 00 c7 44 24 ?? 69 00 00 00 c7 44 24 ?? 70 00 00 00 [0-04] c7 44 24 ?? 5c 00 00 00 c7 44 24 ?? 2e 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}