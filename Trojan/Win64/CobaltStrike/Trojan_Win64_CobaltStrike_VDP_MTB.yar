
rule Trojan_Win64_CobaltStrike_VDP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.VDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 89 48 06 0f b7 4f 08 66 83 e9 07 66 89 48 08 0f b7 4f 0a 66 83 e9 07 66 89 48 0a 0f b7 4f 0c 66 41 2b c9 66 89 48 0c 0f b7 4f 0e 66 2b ca 66 89 48 0e 0f b7 4f 10 66 83 e9 09 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}