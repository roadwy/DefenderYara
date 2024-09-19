
rule Trojan_Win64_FraudLoad_B_MTB{
	meta:
		description = "Trojan:Win64/FraudLoad.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_02_0 = {48 89 5c 24 08 48 89 74 24 10 57 48 83 ec 20 41 8a f8 48 8b f2 48 8b d9 e8 ?? ?? ?? ?? 84 c0 ?? ?? b8 01 00 00 00 ?? ?? 48 8b d6 48 8b cb e8 ?? ?? ?? ?? c6 43 48 00 8b f0 a8 01 ?? ?? 44 8a c7 48 8d 54 24 48 41 80 c8 01 48 8b cb e8 ?? ?? ?? ?? 40 8a d7 48 8b cb e8 ?? ?? ?? ?? 8b c6 48 8b 5c 24 30 48 8b 74 24 38 48 83 c4 20 5f c3 } //3
	condition:
		((#a_02_0  & 1)*3) >=3
 
}