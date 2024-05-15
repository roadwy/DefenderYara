
rule Trojan_Win64_GenCBL_ARA_MTB{
	meta:
		description = "Trojan:Win64/GenCBL.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8d 41 f6 30 44 0c 20 48 ff c1 48 83 f9 08 72 f0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_GenCBL_ARA_MTB_2{
	meta:
		description = "Trojan:Win64/GenCBL.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8d 42 04 30 44 15 e0 48 ff 90 01 01 48 83 fa 90 01 01 72 f0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}