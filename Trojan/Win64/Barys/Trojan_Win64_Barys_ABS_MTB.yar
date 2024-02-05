
rule Trojan_Win64_Barys_ABS_MTB{
	meta:
		description = "Trojan:Win64/Barys.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {f7 eb c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 90 01 01 0f b6 c3 2a c2 04 37 41 30 00 ff c3 4d 8d 40 01 83 fb 90 00 } //05 00 
		$a_03_1 = {49 8b d1 49 8b ca e8 90 01 04 b9 b8 0b 00 00 ff 15 90 01 04 33 c9 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}