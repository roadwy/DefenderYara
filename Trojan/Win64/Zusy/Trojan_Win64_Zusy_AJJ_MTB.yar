
rule Trojan_Win64_Zusy_AJJ_MTB{
	meta:
		description = "Trojan:Win64/Zusy.AJJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c7 0f 1f 40 90 01 01 8d 48 58 41 30 0c 00 48 ff c0 48 83 f8 0b 72 90 00 } //01 00 
		$a_03_1 = {33 c0 0f 1f 84 00 90 01 04 8d 50 58 30 14 08 48 ff c0 48 83 f8 43 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}