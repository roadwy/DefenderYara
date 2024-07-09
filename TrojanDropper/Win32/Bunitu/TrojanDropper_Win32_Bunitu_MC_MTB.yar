
rule TrojanDropper_Win32_Bunitu_MC_MTB{
	meta:
		description = "TrojanDropper:Win32/Bunitu.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c6 2b c8 8b f1 c1 e6 ?? 03 75 ?? 8b c1 c1 e8 ?? 03 45 ?? 03 d9 33 f3 33 f0 c7 05 [0-08] 89 45 ?? 2b d6 8b 45 ?? 29 45 ?? 83 ef ?? 75 ?? 8b 45 ?? 5f 5e 89 10 89 48 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}