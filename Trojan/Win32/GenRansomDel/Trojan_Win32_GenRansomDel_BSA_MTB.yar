
rule Trojan_Win32_GenRansomDel_BSA_MTB{
	meta:
		description = "Trojan:Win32/GenRansomDel.BSA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_00_0 = {2f 00 43 00 20 00 44 00 45 00 4c 00 20 00 2f 00 46 00 20 00 2f 00 51 00 20 00 43 00 3a 00 5c 00 50 00 52 00 4f 00 47 00 52 00 41 00 } //10 /C DEL /F /Q C:\PROGRA
		$a_00_1 = {2e 00 74 00 6d 00 70 00 20 00 3e 00 3e 00 20 00 4e 00 55 00 4c 00 } //1 .tmp >> NUL
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1) >=11
 
}