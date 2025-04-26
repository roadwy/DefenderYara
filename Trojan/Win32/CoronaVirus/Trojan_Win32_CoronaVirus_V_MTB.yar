
rule Trojan_Win32_CoronaVirus_V_MTB{
	meta:
		description = "Trojan:Win32/CoronaVirus.V!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 72 00 64 00 2f 00 73 00 20 00 2f 00 71 00 20 00 63 00 3a 00 5c 00 } //1 cmd /c rd/s /q c:\
		$a_01_1 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 52 00 45 00 47 00 20 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 48 00 4b 00 4c 00 4d 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 20 00 2f 00 66 00 } //1 cmd /c REG DELETE HKLM\Software\ /f
		$a_01_2 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 72 00 64 00 2f 00 73 00 20 00 2f 00 71 00 20 00 64 00 3a 00 5c 00 } //1 cmd /c rd/s /q d:\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}