
rule Trojan_Win64_Cobaltstrike_RDB_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 b0 01 c6 45 20 00 48 8d 55 20 49 8b ce e8 b3 04 00 00 41 b0 01 c6 45 20 00 48 8d 55 20 49 8b ce e8 50 06 00 00 41 b0 01 c6 45 20 00 48 8d 55 20 49 8b ce e8 ed 07 00 00 41 b0 01 c6 45 20 00 48 8d 55 20 49 8b ce } //00 00 
	condition:
		any of ($a_*)
 
}