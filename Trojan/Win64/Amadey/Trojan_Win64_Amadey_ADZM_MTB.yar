
rule Trojan_Win64_Amadey_ADZM_MTB{
	meta:
		description = "Trojan:Win64/Amadey.ADZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 1b 48 83 7c 24 ?? ?? 48 8d 54 24 ?? 4c 8b c3 48 c7 44 24 ?? ?? ?? ?? ?? 48 0f 47 54 24 ?? 45 33 c9 33 c9 e8 ?? ?? ?? ?? 48 8b 54 24 ?? 8b d8 c1 eb 1f 80 f3 01 48 83 fa 07 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}