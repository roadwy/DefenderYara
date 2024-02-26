
rule Trojan_Win64_StrelaStealer_ASDA_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.ASDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 80 e0 ff 45 20 f2 45 08 e7 45 08 d0 45 30 c7 44 8a } //01 00 
		$a_01_1 = {44 08 c1 80 f1 ff 41 80 ce 01 44 20 f1 41 08 cf } //01 00 
		$a_01_2 = {41 80 f1 01 41 08 d2 41 80 c9 01 41 80 f2 ff 45 20 ca 8a } //01 00 
		$a_01_3 = {41 08 fc 45 08 f5 45 30 ec 45 08 d9 41 80 f1 ff } //00 00 
	condition:
		any of ($a_*)
 
}