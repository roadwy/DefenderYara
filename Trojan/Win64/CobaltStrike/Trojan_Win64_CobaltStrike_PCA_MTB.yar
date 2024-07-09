
rule Trojan_Win64_CobaltStrike_PCA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 44 24 30 48 8d 15 ?? ?? ?? ?? 48 8b 4c 24 30 } //1
		$a_00_1 = {41 b9 40 00 00 00 41 b8 00 30 00 00 48 8b 54 24 28 33 c9 ff 54 24 38 48 8b 8c 24 80 00 00 00 48 89 41 18 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}