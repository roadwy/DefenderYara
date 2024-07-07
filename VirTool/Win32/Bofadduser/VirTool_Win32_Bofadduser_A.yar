
rule VirTool_Win32_Bofadduser_A{
	meta:
		description = "VirTool:Win32/Bofadduser.A,SIGNATURE_TYPE_PEHSTR,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 64 64 69 6e 67 20 75 73 65 72 20 66 61 69 6c 65 64 } //2 Adding user failed
		$a_01_1 = {41 64 64 69 6e 67 20 47 75 65 73 74 20 74 6f 20 74 68 65 20 6c 6f 63 61 6c 20 6d 61 63 68 69 6e 65 } //5 Adding Guest to the local machine
		$a_01_2 = {41 64 64 69 6e 67 20 75 73 65 72 } //1 Adding user
		$a_01_3 = {23 62 6f 66 73 74 6f 70 } //1 #bofstop
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=9
 
}