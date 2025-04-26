
rule Trojan_Win64_Winnti_dha{
	meta:
		description = "Trojan:Win64/Winnti!dha,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 73 79 73 70 72 65 70 5c 63 72 79 70 74 62 61 73 65 2e 64 6c 6c } //2 %s\sysprep\cryptbase.dll
		$a_01_1 = {2f 00 6f 00 6f 00 62 00 65 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 20 00 2f 00 71 00 75 00 69 00 74 00 } //2 /oobe /quiet /quit
		$a_01_2 = {4d 6f 6e 69 74 6f 72 69 6e 67 20 6f 66 20 48 61 72 64 77 61 72 65 73 20 41 6e 64 20 41 75 74 6f 6d 61 74 69 63 61 6c 6c 79 20 55 70 64 61 74 65 73 20 54 68 65 20 44 65 76 69 63 65 20 44 72 69 76 65 72 73 } //2 Monitoring of Hardwares And Automatically Updates The Device Drivers
		$a_01_3 = {4c 6f 6f 6b 75 70 41 63 63 6f 75 6e 74 53 69 64 41 } //2 LookupAccountSidA
		$a_01_4 = {52 00 55 00 4e 00 41 00 53 00 } //2 RUNAS
		$a_01_5 = {77 69 6e 64 30 77 73 } //2 wind0ws
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}