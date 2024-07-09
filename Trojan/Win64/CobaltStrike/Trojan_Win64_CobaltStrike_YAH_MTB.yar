
rule Trojan_Win64_CobaltStrike_YAH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d 00 04 00 00 0f ba f8 0a 41 88 04 24 49 ff c4 84 db 74 31 49 8d 55 01 48 8b c7 48 81 fa 00 10 00 00 72 19 48 83 c2 27 48 8b 7f f8 48 2b c7 48 83 c0 f8 48 83 f8 1f 0f 87 ?? ?? ?? ?? 48 8b cf e8 ?? ?? ?? ?? 41 ff c6 48 ff c6 41 81 fe 58 1b 00 00 bb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}