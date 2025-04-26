
rule Trojan_Win64_Mikey_ASJ_MTB{
	meta:
		description = "Trojan:Win64/Mikey.ASJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b c8 ff 15 ?? ?? ?? ?? 45 33 c9 4c 89 64 24 28 4c 8d 05 ?? ?? ?? ?? 44 89 64 24 20 33 d2 33 c9 ff 15 ?? ?? ?? ?? 48 85 c0 75 1d 48 8d ?? ?? ?? ?? 00 4c 8b a4 24 a8 00 00 00 48 83 c4 70 41 5f 41 5e 5d e9 ?? ?? ?? ?? ba ff ff ff ff 48 8b c8 ff 15 } //4
		$a_01_1 = {53 65 72 76 69 63 65 4d 61 69 6e } //1 ServiceMain
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}