
rule Trojan_Win32_DelExe_C{
	meta:
		description = "Trojan:Win32/DelExe.C,SIGNATURE_TYPE_PEHSTR_EXT,08 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 69 74 6c 65 20 57 69 4e 64 4f 77 53 20 4b 69 4c 4c 65 52 20 4d 61 44 65 20 42 79 20 48 54 43 2e 53 70 4c 69 6e 54 65 72 43 65 4c 4c } //3 title WiNdOwS KiLLeR MaDe By HTC.SpLinTerCeLL
		$a_01_1 = {44 65 6c 20 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 20 2f 71 } //2 Del C:\WINDOWS\system32\cmd.exe /q
		$a_01_2 = {53 54 41 52 54 20 2f 6d 61 78 20 68 74 74 70 3a 2f 2f } //1 START /max http://
		$a_01_3 = {52 45 4e 20 2a 2e 44 4f 43 20 2a 2e 6a 73 } //2 REN *.DOC *.js
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}