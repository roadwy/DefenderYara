
rule Backdoor_Win32_Datcaen_A{
	meta:
		description = "Backdoor:Win32/Datcaen.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 6d 73 6f 65 72 74 32 2e 62 61 74 00 } //1
		$a_03_1 = {68 f4 01 00 00 ff 15 90 01 04 be 04 28 00 00 56 8d 45 90 01 01 53 50 e8 90 01 04 83 c4 0c 53 53 53 53 53 ff 55 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}