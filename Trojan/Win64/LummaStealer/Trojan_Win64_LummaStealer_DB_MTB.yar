
rule Trojan_Win64_LummaStealer_DB_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b cb c1 e9 02 ff c1 44 6b c1 32 8b cb 83 e1 03 6b d1 32 83 c2 0a } //1
		$a_03_1 = {48 89 7c 24 ?? 48 89 44 24 ?? 48 89 74 24 ?? 4c 89 7c 24 ?? c7 44 24 ?? ?? ?? ?? ?? c7 44 24 ?? ?? ?? ?? ?? 44 89 44 24 ?? 89 54 24 ?? 41 b9 ?? ?? ?? ?? 4d 8b 06 48 8d 15 ?? ?? ?? ?? 33 c9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}