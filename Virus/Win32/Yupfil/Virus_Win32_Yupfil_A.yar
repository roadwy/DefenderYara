
rule Virus_Win32_Yupfil_A{
	meta:
		description = "Virus:Win32/Yupfil.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {69 6a 6c 47 65 74 4c 69 62 56 65 72 73 69 6f 6e } //1 ijlGetLibVersion
		$a_01_1 = {69 6a 6c 49 6e 69 74 } //1 ijlInit
		$a_01_2 = {69 6a 6c 46 72 65 65 } //1 ijlFree
		$a_01_3 = {69 6a 6c 52 65 61 64 } //1 ijlRead
		$a_01_4 = {69 6a 6c 57 72 69 74 65 } //1 ijlWrite
		$a_01_5 = {69 6a 6c 45 72 72 6f 72 53 74 72 } //1 ijlErrorStr
		$a_00_6 = {6d 66 63 33 32 2e 64 6c 6c 00 } //1 晭㍣⸲汤l
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}