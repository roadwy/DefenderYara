
rule PWS_Win32_Sinowal_gen_R{
	meta:
		description = "PWS:Win32/Sinowal.gen!R,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 45 08 83 e8 04 50 8b 4d 10 51 8b 55 0c 52 8b 45 08 50 e8 90 01 02 ff ff 8b e5 5d c2 0c 00 90 00 } //01 00 
		$a_02_1 = {8b c0 55 8b ec 83 ec 90 01 01 c7 45 fc ff ff ff ff c7 45 bc 00 00 00 00 eb 09 8b 45 bc 83 c0 01 89 45 bc 83 7d bc 90 01 01 73 0e 90 90 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}