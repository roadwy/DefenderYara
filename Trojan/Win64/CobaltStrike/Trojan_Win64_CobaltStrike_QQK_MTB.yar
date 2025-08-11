
rule Trojan_Win64_CobaltStrike_QQK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.QQK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 01 ef 89 bd e2 fe ff ff 4c 31 8d c7 fe ff ff 4c 8b 9d 4b ff ff ff 66 89 c2 8b 95 31 ff ff ff 21 c1 89 8d 0f ff ff ff 4c 2b bd 25 ff ff ff 0f b6 c8 89 c0 4c 31 bd ?? ?? ?? ?? 49 c7 c2 12 d2 00 00 4c 89 3d 9e e6 02 00 4c 8b 85 ?? ?? ?? ?? 4c 01 c1 49 c7 c0 21 e0 00 00 89 85 10 ff ff ff 48 ff 04 24 48 83 3c 24 03 0f 8e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}