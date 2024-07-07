
rule Trojan_Win32_KillMBR_MA_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {79 61 6e 67 72 6f 75 63 68 75 61 6e 39 39 39 40 31 36 33 2e 63 6f 6d } //2 yangrouchuan999@163.com
		$a_01_1 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 68 61 73 20 62 65 65 6e 20 74 72 61 73 68 65 64 20 62 79 20 74 68 65 20 43 52 54 59 59 74 72 6f 6a 61 6e } //2 Your computer has been trashed by the CRTYYtrojan
		$a_01_2 = {4e 79 61 6e 20 43 61 74 2e 2e 2e } //2 Nyan Cat...
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}