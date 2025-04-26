
rule Trojan_Win64_CobaltStrike_MID_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b c2 4d 8d 5b 01 99 41 ff c2 41 f7 f8 48 63 c2 0f b6 4c 04 50 42 32 8c 1c ?? ?? 00 00 42 88 8c 1c ?? ?? 00 00 41 81 fa 7c 03 00 00 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}