
rule Backdoor_Win32_Prinisakat_A{
	meta:
		description = "Backdoor:Win32/Prinisakat.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3a 6c 6f 6f 70 90 02 04 64 65 6c 20 25 73 90 02 04 69 66 20 65 78 69 73 74 20 25 73 20 67 6f 74 6f 20 6c 6f 6f 70 90 00 } //1
		$a_00_1 = {2f 00 73 00 65 00 61 00 72 00 63 00 68 00 2e 00 68 00 74 00 6d 00 6c 00 3f 00 69 00 70 00 3d 00 } //1 /search.html?ip=
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}