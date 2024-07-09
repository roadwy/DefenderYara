
rule Trojan_Win32_Darkes_A{
	meta:
		description = "Trojan:Win32/Darkes.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {65 63 68 6f 20 5b 41 75 74 6f 52 75 6e 5d 20 3e 20 25 25 ?? 3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //1
		$a_00_1 = {65 63 68 6f 20 73 74 61 72 74 20 22 22 20 25 30 3e 3e 25 53 79 73 74 65 6d 44 72 69 76 65 25 5c 41 55 54 4f 45 58 45 43 2e 42 41 54 } //1 echo start "" %0>>%SystemDrive%\AUTOEXEC.BAT
		$a_00_2 = {46 4f 52 20 2f 46 20 22 74 6f 6b 65 6e 73 3d 31 2c 2a 20 64 65 6c 69 6d 73 3d 3a 20 22 20 25 25 6a 20 69 6e 20 28 49 6e 66 4c 69 73 74 5f 65 78 65 2e 74 78 74 29 20 64 6f 20 63 6f 70 79 20 2f 79 20 25 30 20 22 25 25 6a 3a 25 25 6b 22 } //1 FOR /F "tokens=1,* delims=: " %%j in (InfList_exe.txt) do copy /y %0 "%%j:%%k"
		$a_00_3 = {5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 20 2f 76 20 44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 31 20 2f 66 } //1 \Policies\System /v DisableTaskMgr /t REG_SZ /d 1 /f
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}