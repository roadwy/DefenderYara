
rule Trojan_Win32_Nekark_GPA_MTB{
	meta:
		description = "Trojan:Win32/Nekark.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_81_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 20 48 69 64 64 65 6e 20 2d 6e 6f 70 20 2d 65 70 20 62 79 70 61 73 73 20 2d 4e 6f 45 78 69 74 20 2d 45 } //2 powershell.exe -W Hidden -nop -ep bypass -NoExit -E
		$a_81_1 = {4a 41 42 6f 41 47 30 41 52 77 42 31 41 46 67 41 } //2 JABoAG0ARwB1AFgA
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}