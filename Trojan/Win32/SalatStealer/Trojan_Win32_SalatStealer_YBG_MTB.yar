
rule Trojan_Win32_SalatStealer_YBG_MTB{
	meta:
		description = "Trojan:Win32/SalatStealer.YBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 6c 65 65 70 20 70 61 74 63 68 20 64 65 74 65 63 74 65 64 } //1 Sleep patch detected
		$a_01_1 = {56 4d 20 64 65 74 65 63 74 65 64 } //1 VM detected
		$a_01_2 = {44 65 62 75 67 67 65 72 20 64 65 74 65 63 74 65 64 } //1 Debugger detected
		$a_01_3 = {44 65 63 72 79 70 74 69 6f 6e 20 53 55 43 43 45 53 53 } //1 Decryption SUCCESS
		$a_01_4 = {20 3c 20 32 47 42 29 21 20 45 78 } //4  < 2GB)! Ex
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*4) >=8
 
}