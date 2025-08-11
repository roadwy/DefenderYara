
rule Trojan_Win64_Skoppy_B_dha{
	meta:
		description = "Trojan:Win64/Skoppy.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 56 42 6f 78 4d 69 6e 69 52 64 72 44 4e } //2 \\.\VBoxMiniRdrDN
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 56 4d 77 61 72 65 2c 20 49 6e 63 2e 5c 56 4d 77 61 72 65 20 54 6f 6f 6c 73 } //2 SOFTWARE\VMware, Inc.\VMware Tools
		$a_01_2 = {63 6f 5f 73 79 73 5f 63 6f 5f } //4 co_sys_co_
		$a_01_3 = {25 73 5c 6d 69 63 72 6f 2e 6c 6f 67 2e 7a 69 70 } //4 %s\micro.log.zip
		$a_01_4 = {63 6d 64 20 2f 63 20 73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 22 43 6c 65 61 6e 53 79 73 6c 6f 67 54 61 73 6b 22 20 2f 74 72 20 22 72 75 6e 64 6c 6c 33 32 20 25 73 2c 73 22 } //8 cmd /c schtasks /create /tn "CleanSyslogTask" /tr "rundll32 %s,s"
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*4+(#a_01_3  & 1)*4+(#a_01_4  & 1)*8) >=8
 
}