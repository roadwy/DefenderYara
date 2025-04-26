
rule TrojanSpy_Win32_Sodast_A{
	meta:
		description = "TrojanSpy:Win32/Sodast.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {58 2d 52 61 6e 64 3a 20 } //1 X-Rand: 
		$a_01_1 = {21 63 6d 64 2e 65 78 65 20 2f 43 20 63 3a 5c } //1 !cmd.exe /C c:\
		$a_01_2 = {46 43 49 41 64 64 46 69 6c 65 } //1 FCIAddFile
		$a_01_3 = {50 4f 53 54 20 25 73 20 48 54 54 50 2f 31 2e 30 } //1 POST %s HTTP/1.0
		$a_01_4 = {66 6f 78 5c 50 72 6f 66 69 6c 65 73 } //1 fox\Profiles
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}