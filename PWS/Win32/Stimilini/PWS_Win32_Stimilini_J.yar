
rule PWS_Win32_Stimilini_J{
	meta:
		description = "PWS:Win32/Stimilini.J,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0c 53 74 65 61 6d 43 6f 6f 6b 69 65 73 } //1
		$a_01_1 = {3f 3f 32 35 33 37 36 33 32 35 33 37 36 33 } //1 ??253763253763
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}