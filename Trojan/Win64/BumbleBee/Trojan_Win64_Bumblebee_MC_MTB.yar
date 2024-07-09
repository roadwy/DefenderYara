
rule Trojan_Win64_Bumblebee_MC_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 0f af 43 24 41 8b d0 c1 ea 10 88 14 01 41 8b d0 44 01 53 40 48 8b 05 ?? ?? ?? ?? c1 ea 08 8b 88 f4 00 00 00 41 33 ca 29 8b b4 00 00 00 8b 05 ?? ?? ?? ?? 48 8b 0d ?? ?? ?? ?? 05 6e e7 e9 ff 09 05 ?? ?? ?? ?? 8b 41 34 2d ?? ?? ?? ?? 01 81 ?? ?? ?? ?? 48 63 4b 40 48 8b 43 78 88 14 01 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}