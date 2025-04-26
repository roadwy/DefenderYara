
rule Trojan_Win64_CobaltStrike_PT_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 56 57 48 81 ec c8 03 00 00 48 8b 05 27 49 00 00 48 33 c4 48 89 84 24 b0 03 00 00 48 8d 05 75 2e 00 00 48 89 84 24 c8 00 00 00 48 8d 05 76 2e 00 00 48 89 84 24 c0 00 00 00 48 8d 84 24 b0 01 00 00 48 8d 0d 67 2e 00 00 48 8b f8 48 8b f1 b9 ?? 00 00 00 f3 a4 48 8d 84 24 ?? 01 00 00 48 8b f8 33 c0 b9 ?? 00 00 00 f3 aa 48 8d 84 24 b0 02 00 00 48 8d 0d 47 2e 00 00 48 8b f8 48 8b f1 b9 ?? 00 00 00 f3 a4 48 8d 84 24 ?? 02 00 00 48 8b f8 33 c0 b9 ?? 00 00 00 f3 aa 48 8d 0d 2f 2e 00 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}