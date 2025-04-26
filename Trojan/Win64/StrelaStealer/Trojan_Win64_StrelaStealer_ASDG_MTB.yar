
rule Trojan_Win64_StrelaStealer_ASDG_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.ASDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 57 41 56 41 55 41 54 56 57 55 53 b8 ?? ?? 00 00 e8 ?? ?? ?? 00 48 29 c4 48 8d 84 24 ?? ?? 00 00 48 89 c1 48 8d 15 ?? ?? ?? 00 41 b8 04 00 00 00 e8 ?? ?? ?? 00 48 8d 0d ?? ?? ?? 00 48 89 ca 48 81 c2 } //5
		$a_03_1 = {41 57 41 56 41 55 41 54 56 57 55 53 48 81 ec ?? ?? 00 00 48 8d 84 24 ?? ?? 00 00 48 89 c1 48 8d 15 ?? ?? ?? 00 41 b8 04 00 00 00 e8 ?? ?? ?? 00 48 8d 0d ?? ?? ?? 00 48 89 ca 48 81 c2 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}