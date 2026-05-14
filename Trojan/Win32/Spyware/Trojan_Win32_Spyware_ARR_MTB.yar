
rule Trojan_Win32_Spyware_ARR_MTB{
	meta:
		description = "Trojan:Win32/Spyware.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_81_0 = {77 6d 69 20 3a 3d 20 43 6f 6d 4f 62 6a 47 65 74 28 22 77 69 6e 6d 67 6d 74 73 3a 22 29 } //9 wmi := ComObjGet("winmgmts:")
		$a_81_1 = {71 75 65 72 79 20 3a 3d 20 77 6d 69 2e 45 78 65 63 51 75 65 72 79 28 22 53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } //11 query := wmi.ExecQuery("Select * from Win32_Process")
	condition:
		((#a_81_0  & 1)*9+(#a_81_1  & 1)*11) >=20
 
}