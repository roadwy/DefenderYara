
rule Trojan_Win64_CobaltStrike_DDZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.DDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 d1 43 0f b6 0c 0b 42 0f b6 04 0a 43 88 04 0b 42 88 0c 0a 41 0f b6 81 00 01 00 00 42 0f b6 14 08 41 0f b6 81 ?? ?? ?? ?? 42 0f b6 0c 08 03 d1 81 e2 ff 00 00 80 7d ?? ff ca 81 ca 00 ff ff ff ff c2 48 63 c2 49 ff c2 42 0f b6 0c 08 41 30 4a ff 49 ff c8 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}