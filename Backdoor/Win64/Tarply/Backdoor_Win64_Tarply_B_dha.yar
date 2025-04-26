
rule Backdoor_Win64_Tarply_B_dha{
	meta:
		description = "Backdoor:Win64/Tarply.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 47 53 45 53 53 49 4f 4e 49 44 3d } //2 RGSESSIONID=
		$a_01_1 = {77 72 69 74 65 20 64 6f 6e 65 20 5c 72 5c 6e } //1 write done \r\n
		$a_01_2 = {4d 79 4e 61 74 69 76 65 4d 6f 64 75 6c 65 2e 64 6c 6c } //1 MyNativeModule.dll
		$a_01_3 = {2e 3f 41 56 43 48 65 6c 6c 6f 57 6f 72 6c 64 40 40 } //1 .?AVCHelloWorld@@
		$a_00_4 = {63 6d 64 24 00 00 00 00 72 00 00 00 00 00 00 00 75 70 6c 6f 61 64 24 } //4
		$a_00_5 = {63 61 6e 27 74 20 6f 70 65 6e 20 66 69 6c 65 20 3a 20 00 00 00 00 00 00 64 6f 77 6e 6c 6f 61 64 24 } //4
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*4+(#a_00_5  & 1)*4) >=4
 
}