
rule Backdoor_Win32_Farfli_BQ_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 4c 04 04 8b 14 24 02 d0 32 d1 88 54 04 04 40 3d 8b 00 00 00 72 } //3
		$a_01_1 = {41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 73 00 5c 00 56 00 4d 00 77 00 61 00 72 00 65 00 48 00 6f 00 73 00 74 00 4f 00 70 00 65 00 6e 00 2e 00 65 00 78 00 65 00 } //2 Applications\VMwareHostOpen.exe
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}