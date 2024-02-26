
rule Trojan_Win64_GenCBL_ARA_MTB{
	meta:
		description = "Trojan:Win64/GenCBL.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8d 41 f6 30 44 0c 20 48 ff c1 48 83 f9 08 72 f0 } //00 00 
	condition:
		any of ($a_*)
 
}