
rule PWS_Win32_Kuluoz_gen_A{
	meta:
		description = "PWS:Win32/Kuluoz.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 fc 01 6a 15 be 0f 00 00 00 68 } //01 00 
		$a_01_1 = {26 61 6b 6b 3d } //01 00  &akk=
		$a_01_2 = {7c 28 66 74 70 73 3a 5c 2f 5c 2f 29 29 3f 28 3f 3c 4e 48 6f 73 74 3e } //00 00  |(ftps:\/\/))?(?<NHost>
	condition:
		any of ($a_*)
 
}