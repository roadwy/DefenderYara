
rule Trojan_Win64_Bumblebee_MZV_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.MZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {22 c8 48 8b 44 24 78 41 30 0c 00 43 8d 04 1b 48 63 c8 48 8b 05 ?? ?? ?? ?? 8a 14 48 02 16 48 8d 76 08 48 8b 05 ?? ?? ?? ?? 02 54 24 60 42 32 14 28 4d 8d 6d ?? 41 30 17 4d 03 f9 48 8b 04 24 0f b7 80 ?? ?? ?? ?? 44 3b d0 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}