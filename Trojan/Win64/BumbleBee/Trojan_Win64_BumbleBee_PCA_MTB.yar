
rule Trojan_Win64_BumbleBee_PCA_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.PCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 55 53 56 57 41 54 41 55 41 56 41 57 48 8d 6c 24 ?? 48 81 ec ?? ?? ?? ?? 8b d9 ff 15 ?? ?? ?? ?? bf ?? ?? ?? ?? 33 d2 48 8b c8 44 8b c7 ff 15 ?? ?? ?? ?? 44 8b c7 33 d2 48 8b c8 48 89 05 ?? ?? ?? ?? e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}