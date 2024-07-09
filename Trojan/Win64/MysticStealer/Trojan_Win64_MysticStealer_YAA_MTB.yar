
rule Trojan_Win64_MysticStealer_YAA_MTB{
	meta:
		description = "Trojan:Win64/MysticStealer.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 89 c9 ff c1 41 0f af c9 f6 c1 01 41 0f 94 c1 44 30 ca 84 d2 41 b9 a8 08 00 00 ba ?? ?? ?? ?? 49 0f 45 d1 f6 c1 01 48 89 d1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}