
rule Trojan_Win32_Doina_KK_MTB{
	meta:
		description = "Trojan:Win32/Doina.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 33 20 3e 20 6e 75 6c 20 26 20 64 65 6c 20 22 25 73 22 } //10 cmd /c ping 127.0.0.1 -n 3 > nul & del "%s"
		$a_81_1 = {2f 43 20 70 6f 77 65 72 73 68 65 6c 6c 20 2d 69 6e 70 75 74 66 6f 72 6d 61 74 20 6e 6f 6e 65 20 2d 6f 75 74 70 75 74 66 6f 72 6d 61 74 20 6e 6f 6e 65 20 2d 4e 6f 6e 49 6e 74 65 72 61 63 74 69 76 65 20 2d 43 6f 6d 6d 61 6e 64 20 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 22 25 73 22 } //8 /C powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath "%s"
		$a_01_2 = {44 3a 5c 44 65 76 5c 49 56 5c 50 72 6f 6a 65 63 74 5c 55 70 64 61 74 65 42 69 6e } //5 D:\Dev\IV\Project\UpdateBin
		$a_81_3 = {41 70 70 49 6e 69 74 5f 44 4c 4c 73 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 75 70 64 61 74 65 64 21 } //2 AppInit_DLLs successfully updated!
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*8+(#a_01_2  & 1)*5+(#a_81_3  & 1)*2) >=25
 
}