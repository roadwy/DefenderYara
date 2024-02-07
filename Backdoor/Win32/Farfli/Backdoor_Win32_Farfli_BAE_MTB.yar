
rule Backdoor_Win32_Farfli_BAE_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {89 45 08 8d 45 dc c6 45 dc 57 50 57 c6 45 dd 72 c6 45 de 69 c6 45 df 74 c6 45 e0 65 c6 45 e1 46 c6 45 e2 69 c6 45 e3 6c c6 45 e4 65 ff d6 } //01 00 
		$a_01_1 = {31 2e 65 78 65 } //01 00  1.exe
		$a_01_2 = {75 73 65 72 2e 71 7a 6f 6e 65 2e 71 71 2e 63 6f 6d } //00 00  user.qzone.qq.com
	condition:
		any of ($a_*)
 
}