
rule PWS_Win32_Populf_C{
	meta:
		description = "PWS:Win32/Populf.C,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 01 00 00 00 e8 41 ef ff ff 8b 55 ec b8 68 bc 40 00 b9 e0 9d 40 00 e8 67 a5 ff ff 8d 55 e8 b8 01 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}