
rule Trojan_Win64_Soulbind_GVA_MTB{
	meta:
		description = "Trojan:Win64/Soulbind.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 76 20 2f 63 20 53 65 74 20 46 66 4c 6f 6c 3d 63 6d 64 20 26 20 21 46 66 4c 6f 6c 21 20 3c 20 4f 66 66 69 63 65 72 73 2e 78 6c 61 } //1 cmd /v /c Set FfLol=cmd & !FfLol! < Officers.xla
		$a_01_1 = {73 63 2e 65 78 65 20 2f 3f 61 6c 6b 73 6a 64 66 68 6a 66 38 33 34 38 32 37 34 33 35 } //2 sc.exe /?alksjdfhjf834827435
		$a_01_2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 61 64 76 70 61 63 6b 2e 64 6c 6c 2c 44 65 6c 4e 6f 64 65 52 75 6e 44 4c 4c 33 32 20 22 25 73 22 } //1 rundll32.exe %sadvpack.dll,DelNodeRunDLL32 "%s"
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //1 Software\Microsoft\Windows\CurrentVersion\RunOnce
		$a_01_4 = {50 65 6e 64 69 6e 67 46 69 6c 65 52 65 6e 61 6d 65 4f 70 65 72 61 74 69 6f 6e 73 } //1 PendingFileRenameOperations
		$a_01_5 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 65 73 73 69 6f 6e 20 4d 61 6e 61 67 65 72 5c 46 69 6c 65 52 65 6e 61 6d 65 4f 70 65 72 61 74 69 6f 6e 73 } //1 System\CurrentControlSet\Control\Session Manager\FileRenameOperations
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}