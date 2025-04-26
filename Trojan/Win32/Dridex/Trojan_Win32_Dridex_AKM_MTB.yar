
rule Trojan_Win32_Dridex_AKM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {50 6c 6f 61 65 73 52 76 6f 6d 6d 6e 72 } //PloaesRvommnr  3
		$a_80_1 = {6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //kernel32.Sleep  3
		$a_80_2 = {6d 59 41 50 50 2e 45 58 45 } //mYAPP.EXE  3
		$a_80_3 = {43 68 72 6f 6d 65 6e 73 75 62 6d 65 6e 75 37 36 53 74 6f 72 65 31 36 34 65 6d 61 6e 61 67 65 } //Chromensubmenu76Store164emanage  3
		$a_80_4 = {70 61 74 56 65 72 73 69 6f 6e 73 61 69 64 74 65 73 74 65 72 } //patVersionsaidtester  3
		$a_80_5 = {4a 65 74 45 6e 64 53 65 73 73 69 6f 6e } //JetEndSession  3
		$a_80_6 = {43 72 79 70 74 53 49 50 43 72 65 61 74 65 49 6e 64 69 72 65 63 74 44 61 74 61 } //CryptSIPCreateIndirectData  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}