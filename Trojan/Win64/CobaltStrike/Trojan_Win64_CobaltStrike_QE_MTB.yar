
rule Trojan_Win64_CobaltStrike_QE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.QE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff c0 88 04 0c 83 c2 90 01 01 48 ff c1 48 83 f9 90 01 01 7c 90 00 } //01 00 
		$a_03_1 = {33 c9 4d 8d 49 90 01 01 48 83 f8 90 01 01 48 0f 45 c8 0f b6 04 0c 41 30 41 90 01 01 48 8d 41 90 01 01 48 83 ea 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}