
rule Trojan_Win64_NukeSpeed_MK_MTB{
	meta:
		description = "Trojan:Win64/NukeSpeed.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 54 04 90 02 01 48 ff c0 42 32 90 02 03 48 83 f8 90 02 01 48 0f 44 c1 41 88 14 18 49 ff c0 49 83 f8 90 02 01 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_NukeSpeed_MK_MTB_2{
	meta:
		description = "Trojan:Win64/NukeSpeed.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 74 05 f7 90 02 01 80 74 05 f8 90 1b 00 48 83 c0 02 48 83 f8 90 02 01 7c 90 00 } //01 00 
		$a_03_1 = {41 0f b6 4c 10 90 02 01 48 ff c2 41 32 cc 48 ff cf 88 4a ff 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}