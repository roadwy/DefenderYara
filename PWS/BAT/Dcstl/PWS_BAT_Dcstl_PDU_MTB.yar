
rule PWS_BAT_Dcstl_PDU_MTB{
	meta:
		description = "PWS:BAT/Dcstl.PDU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0c 29 01 00 48 89 4c 24 08 48 83 ec 38 b9 17 00 00 00 ff 90 01 04 00 85 c0 74 07 b9 02 00 00 00 cd 29 48 8d 0d 06 8c 02 00 e8 90 00 } //01 00 
		$a_03_1 = {48 8b 85 c8 04 00 00 48 89 44 24 60 c7 44 24 50 15 00 00 40 c7 44 24 54 01 00 00 00 ff 90 01 04 00 83 f8 01 48 8d 44 24 50 48 89 90 00 } //01 00 
		$a_03_2 = {48 8b c4 48 90 01 03 48 90 01 03 48 90 01 03 48 90 01 03 41 56 48 90 01 03 00 00 00 48 8d 48 88 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}