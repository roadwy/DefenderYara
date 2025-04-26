
rule Backdoor_Win32_Mangwam_A{
	meta:
		description = "Backdoor:Win32/Mangwam.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 69 6e 73 65 74 2e 69 6e 69 00 } //1
		$a_01_1 = {64 6f 77 6e 65 78 65 6e 61 6d 65 00 } //1 潤湷硥湥浡e
		$a_01_2 = {67 65 74 77 6f 72 6b 2e 70 68 70 3f 6d 61 63 68 69 6e 65 69 64 3d 00 } //1
		$a_01_3 = {6d 61 63 68 69 6e 65 69 64 2e 70 68 70 3f 63 68 65 63 6b 73 74 72 3d 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}