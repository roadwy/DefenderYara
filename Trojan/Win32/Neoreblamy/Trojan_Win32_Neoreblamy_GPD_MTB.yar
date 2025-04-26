
rule Trojan_Win32_Neoreblamy_GPD_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_81_0 = {79 73 47 78 48 74 71 74 5a 5a 69 56 6b 54 6d 53 73 } //3 ysGxHtqtZZiVkTmSs
		$a_81_1 = {6f 45 75 58 5a 57 4c 6e 69 54 65 } //2 oEuXZWLniTe
		$a_81_2 = {58 54 4a 73 47 46 44 6f 4a 74 6e 4e 45 46 } //1 XTJsGFDoJtnNEF
		$a_81_3 = {4d 4b 6a 55 66 73 74 64 62 6d 6b 57 53 78 68 77 61 } //1 MKjUfstdbmkWSxhwa
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=7
 
}