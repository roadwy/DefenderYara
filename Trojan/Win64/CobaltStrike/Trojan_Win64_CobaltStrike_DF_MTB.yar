
rule Trojan_Win64_CobaltStrike_DF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 4c 03 ?? 48 ff c0 41 3a 4c 03 ?? 0f 85 ?? ?? ?? ?? 48 83 f8 ?? 75 } //1
		$a_03_1 = {30 10 ff c1 48 8d 40 ?? 83 f9 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}