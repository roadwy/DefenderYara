
rule Backdoor_Win32_Darkddoser_D{
	meta:
		description = "Backdoor:Win32/Darkddoser.D,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //5 :\autorun.inf
		$a_01_1 = {64 64 6f 73 65 72 } //5 ddoser
		$a_01_2 = {41 44 44 4e 45 57 7c 49 64 6c 65 } //1 ADDNEW|Idle
		$a_01_3 = {44 4f 57 4e 43 4f 4d 50 7c } //1 DOWNCOMP|
		$a_01_4 = {53 59 4e 53 74 61 72 74 } //1 SYNStart
		$a_01_5 = {55 53 42 7c 49 6e 66 65 63 74 65 64 20 44 72 69 76 65 } //1 USB|Infected Drive
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=13
 
}