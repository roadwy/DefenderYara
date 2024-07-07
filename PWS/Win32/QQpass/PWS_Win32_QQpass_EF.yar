
rule PWS_Win32_QQpass_EF{
	meta:
		description = "PWS:Win32/QQpass.EF,SIGNATURE_TYPE_PEHSTR,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {00 53 68 61 72 65 64 73 2e 64 6c 6c } //1 匀慨敲獤搮汬
		$a_01_1 = {5c 43 6f 6d 6d 6f 6e 5c 69 65 78 70 6c 6f 72 65 2e 65 78 } //1 \Common\iexplore.ex
		$a_01_2 = {2f 47 6f 2e 61 73 68 78 3f 4d 61 63 3d } //1 /Go.ashx?Mac=
		$a_01_3 = {83 1b 40 84 0f } //1
		$a_01_4 = {26 55 73 65 72 49 64 3d 31 34 26 42 61 74 65 3d } //1 &UserId=14&Bate=
		$a_01_5 = {51 2d 24 2d 44 4c 4c } //1 Q-$-DLL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}