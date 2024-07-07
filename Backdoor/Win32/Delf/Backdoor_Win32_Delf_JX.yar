
rule Backdoor_Win32_Delf_JX{
	meta:
		description = "Backdoor:Win32/Delf.JX,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {5b 50 72 69 6e 74 20 53 63 72 65 65 6e 5d } //1 [Print Screen]
		$a_01_1 = {5c 77 61 75 61 63 6c 74 2e 6c 6e 6b } //2 \wauaclt.lnk
		$a_01_2 = {77 65 62 63 61 6d 66 61 69 6c } //1 webcamfail
		$a_01_3 = {3a 4f 6e 6c 69 6e 65 3a } //1 :Online:
		$a_01_4 = {66 69 72 73 74 62 6d 70 } //1 firstbmp
		$a_01_5 = {77 61 75 61 63 6c 74 2d 2e 65 78 65 } //2 wauaclt-.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2) >=7
 
}