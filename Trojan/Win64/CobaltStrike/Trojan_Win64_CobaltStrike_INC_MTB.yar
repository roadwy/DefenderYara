
rule Trojan_Win64_CobaltStrike_INC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.INC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 85 fe 17 00 00 89 c2 8b 85 e8 18 00 00 48 98 88 94 05 b0 07 00 00 8b 85 e8 18 00 00 48 98 0f b6 84 05 b0 07 00 00 32 85 ff 18 00 00 89 c2 8b 85 e8 18 00 00 48 98 88 94 05 b0 07 00 00 80 85 ff 18 00 00 01 83 85 e8 18 00 00 01 8b 85 e8 18 00 00 3d 1f 08 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}