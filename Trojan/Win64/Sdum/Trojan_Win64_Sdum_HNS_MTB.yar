
rule Trojan_Win64_Sdum_HNS_MTB{
	meta:
		description = "Trojan:Win64/Sdum.HNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {c7 85 b0 05 00 00 a2 01 00 00 48 89 9d b8 05 00 00 48 89 9d c8 05 00 00 48 89 9d d0 05 00 00 48 89 9d c8 05 00 00 48 c7 85 d0 05 00 00 0f 00 00 00 88 9d b8 05 00 00 44 8d 43 0c } //02 00 
		$a_01_1 = {c7 45 98 65 00 00 00 48 89 5d a0 0f 57 c0 66 0f 7f 45 b0 } //00 00 
	condition:
		any of ($a_*)
 
}