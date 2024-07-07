
rule Trojan_Win64_CobaltStrike_FN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.FN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 01 48 8d 49 90 01 01 ff c0 3d 90 01 04 72 90 00 } //1
		$a_03_1 = {41 0f b6 14 18 41 8d 04 12 44 0f b6 d0 42 0f b6 04 11 41 88 04 18 42 88 14 11 41 0f b6 0c 18 48 03 ca 0f b6 c1 0f b6 4c 04 90 01 01 41 30 49 ff 49 83 eb 90 01 01 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}