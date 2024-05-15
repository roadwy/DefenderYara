
rule Trojan_Win32_Fragtor_NA_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 05 00 "
		
	strings :
		$a_81_0 = {61 69 64 77 66 5f 69 76 66 6f 72 75 } //05 00  aidwf_ivforu
		$a_81_1 = {62 75 79 79 64 5f 61 73 66 6f 64 76 } //05 00  buyyd_asfodv
		$a_81_2 = {63 76 79 64 75 65 5f 61 75 66 64 66 75 } //05 00  cvydue_aufdfu
		$a_81_3 = {69 62 75 64 6f 64 5f 73 6f 64 6f 67 76 } //00 00  ibudod_sodogv
	condition:
		any of ($a_*)
 
}