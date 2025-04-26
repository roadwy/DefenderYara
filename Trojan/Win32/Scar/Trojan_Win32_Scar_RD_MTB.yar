
rule Trojan_Win32_Scar_RD_MTB{
	meta:
		description = "Trojan:Win32/Scar.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {40 64 65 6c 20 22 63 3a 5c 70 72 6f 67 2e 62 61 74 22 3e 6e 75 6c } //1 @del "c:\prog.bat">nul
		$a_01_1 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 autorun.inf
		$a_01_2 = {52 6f 42 33 72 54 } //1 RoB3rT
		$a_01_3 = {49 6e 66 6f 72 6d 61 63 6a 65 20 6f 20 73 79 73 74 65 6d 69 65 20 62 6f 74 20 76 2e 30 2e 32 } //1 Informacje o systemie bot v.0.2
		$a_01_4 = {4b 65 79 6c 6f 67 67 65 72 20 73 74 61 72 74 65 64 20 6f 6e 20 63 68 61 6e 65 6c 3a 20 25 73 } //1 Keylogger started on chanel: %s
		$a_01_5 = {72 6f 78 2e 77 69 65 63 7a 6f 72 6e 69 77 79 6d 69 61 74 61 63 7a 65 2e 6e 65 74 } //1 rox.wieczorniwymiatacze.net
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}