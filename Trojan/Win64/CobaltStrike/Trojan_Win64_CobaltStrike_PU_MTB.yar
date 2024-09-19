
rule Trojan_Win64_CobaltStrike_PU_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b cd 48 83 f8 ?? 48 0f 45 c8 0f b6 44 0c ?? 30 02 48 8d 41 ?? 48 8d 52 ?? 49 83 e8 ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}