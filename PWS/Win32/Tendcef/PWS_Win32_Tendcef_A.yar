
rule PWS_Win32_Tendcef_A{
	meta:
		description = "PWS:Win32/Tendcef.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {3f 00 76 00 61 00 72 00 65 00 61 00 3d 00 00 00 } //1
		$a_00_1 = {76 00 70 00 61 00 73 00 73 00 3d 00 00 00 } //1
		$a_00_2 = {41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 73 00 5c 00 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 5c 00 00 00 } //1
		$a_01_3 = {44 4e 46 70 61 73 73 00 } //1 乄灆獡s
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}