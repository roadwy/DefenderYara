
rule Trojan_Win64_CobaltStrike_ASL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ASL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 54 24 ?? 03 ca 03 c1 83 f0 08 88 44 24 ?? 48 8b 44 24 ?? 48 ff c0 48 89 44 24 ?? eb } //3
		$a_01_1 = {99 83 e0 01 33 c2 2b c2 48 63 4c 24 } //1
		$a_01_2 = {33 ca 03 c1 25 ff 00 00 00 88 04 24 0f b6 04 24 48 83 c4 18 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}