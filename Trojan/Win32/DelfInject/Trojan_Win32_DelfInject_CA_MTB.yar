
rule Trojan_Win32_DelfInject_CA_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {70 68 69 6c 61 50 49 4e 4f 20 53 6f 66 4e } //03 00  philaPINO SofN
		$a_81_1 = {4d 50 5f 49 33 4d 53 49 53 } //03 00  MP_I3MSIS
		$a_81_2 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //03 00  LoadResource
		$a_81_3 = {6d 67 63 6c 74 2e 68 31 36 2e 72 75 } //03 00  mgclt.h16.ru
		$a_81_4 = {6e 61 75 6d 6f 76 5f 40 6d 61 69 6c 2e 72 75 } //03 00  naumov_@mail.ru
		$a_81_5 = {70 61 73 73 77 6f 72 64 } //03 00  password
		$a_81_6 = {55 6e 69 76 65 72 73 61 6c 50 61 73 73 } //00 00  UniversalPass
	condition:
		any of ($a_*)
 
}