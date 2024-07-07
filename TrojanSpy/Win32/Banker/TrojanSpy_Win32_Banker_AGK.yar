
rule TrojanSpy_Win32_Banker_AGK{
	meta:
		description = "TrojanSpy:Win32/Banker.AGK,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0f 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 72 61 71 75 65 6d 3d 63 68 61 76 65 73 2e 77 61 62 40 67 6d 61 69 6c 2e 63 6f 6d } //5 praquem=chaves.wab@gmail.com
		$a_01_1 = {68 74 74 70 3a 2f 2f 31 38 37 2e 31 30 39 2e 31 36 31 2e 31 36 34 2f 72 33 2e 70 68 70 } //5 http://187.109.161.164/r3.php
		$a_01_2 = {43 61 70 74 75 72 61 20 57 61 62 20 2d 20 62 79 20 73 79 73 76 20 40 32 30 31 32 } //5 Captura Wab - by sysv @2012
		$a_01_3 = {63 3a 5c 54 65 6d 70 5c 77 61 62 2e 74 78 74 } //1 c:\Temp\wab.txt
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1) >=15
 
}