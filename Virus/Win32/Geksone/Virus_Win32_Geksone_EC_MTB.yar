
rule Virus_Win32_Geksone_EC_MTB{
	meta:
		description = "Virus:Win32/Geksone.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {60 9c e8 00 00 00 00 5d 81 ed 07 10 40 00 8d b5 5a 10 40 00 56 68 2c 01 00 00 ff b5 56 10 40 00 } //00 00 
	condition:
		any of ($a_*)
 
}