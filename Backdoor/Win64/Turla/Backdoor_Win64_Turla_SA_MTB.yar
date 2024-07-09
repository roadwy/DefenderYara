
rule Backdoor_Win64_Turla_SA_MTB{
	meta:
		description = "Backdoor:Win64/Turla.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 85 c0 75 ?? 8b cb 49 8b d1 4c 8b 05 ?? ?? ?? ?? 4d 2b c1 0f 1f 44 00 00 8b c1 25 ff 00 00 80 7d 09 ff c8 0d 00 ff ff ff ff c0 42 32 04 02 34 ?? 88 02 ff c1 48 ff c2 83 f9 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}