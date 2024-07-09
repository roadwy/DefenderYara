
rule Trojan_Win32_Dronzho_A{
	meta:
		description = "Trojan:Win32/Dronzho.A,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 04 00 00 "
		
	strings :
		$a_02_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 64 6c 6c 63 61 63 68 65 5c [0-10] 2e 6e 6c 73 } //3
		$a_00_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //1 C:\WINDOWS\svchost.exe
		$a_00_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 63 68 6b 64 73 6b 2e 65 78 65 } //1 C:\WINDOWS\SYSTEM32\chkdsk.exe
		$a_02_3 = {53 56 be 00 04 00 00 57 8d 85 00 f4 ff ff 56 50 ff 15 ?? ?? 40 00 8d 85 00 f0 ff ff 56 50 ff 15 ?? ?? 40 00 8d 85 00 f4 ff ff 50 8d 85 00 f8 ff ff 68 ?? ?? 40 00 50 e8 e4 01 00 00 8d 85 00 f0 ff ff 50 8d 85 00 fc ff ff 68 ?? ?? 40 00 50 e8 cc 01 00 00 8b 35 ?? ?? 40 00 83 c4 18 bb 80 00 00 00 8d 85 00 fc ff ff 53 50 ff d6 8b 3d 04 70 40 00 8d 85 00 fc ff ff 6a 00 50 8d 85 00 f8 ff ff 50 ff d7 8d 85 00 fc ff ff 50 e8 ?? ?? 00 00 59 8d 85 00 fc ff ff 6a 06 50 ff d6 8d 85 00 fc ff ff 50 e8 } //10
	condition:
		((#a_02_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*10) >=15
 
}