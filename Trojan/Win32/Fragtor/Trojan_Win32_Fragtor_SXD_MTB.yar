
rule Trojan_Win32_Fragtor_SXD_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.SXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 05 00 00 "
		
	strings :
		$a_03_0 = {83 7c 24 24 10 8d 4c 24 38 a3 ?? ?? ?? ?? b8 02 00 00 00 66 89 44 24 34 8d 44 24 10 0f 43 44 24 10 } //5
		$a_01_1 = {6b 65 79 6c 6f 67 67 65 72 5c } //10 keylogger\
		$a_01_2 = {2e 5c 6c 6f 67 73 5c 25 59 2d 25 6d 2d 25 64 5f 5f 25 48 2d 25 4d 2d 25 53 2e 6c 6f 67 } //10 .\logs\%Y-%m-%d__%H-%M-%S.log
		$a_01_3 = {5b 50 52 49 4e 54 5f 53 43 52 45 45 4e 5d } //1 [PRINT_SCREEN]
		$a_01_4 = {5b 45 53 43 41 50 45 5d } //1 [ESCAPE]
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=27
 
}