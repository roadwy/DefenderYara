
rule Trojan_Win64_Vidar_AH_MTB{
	meta:
		description = "Trojan:Win64/Vidar.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 34 03 29 ce f7 d6 40 88 34 18 48 ff c3 48 39 da 7f } //30
		$a_01_1 = {0f b6 5c 11 ff 0f b6 74 11 fe 01 f3 01 cb 88 1c 0a 48 ff c1 48 39 c8 7f } //20
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}