
rule Trojan_Win64_Alien_GVK_MTB{
	meta:
		description = "Trojan:Win64/Alien.GVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 76 20 53 68 6f 77 53 75 70 65 72 48 69 64 64 65 6e 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 32 20 2f 66 } //1 /v ShowSuperHidden /t REG_DWORD /d 2 /f
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 63 6f 6d 6d 61 6e 64 20 22 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 63 6d 64 20 2d 41 72 67 75 6d 65 6e 74 4c 69 73 74 20 27 2f 73 2c 2f 63 } //1 powershell -windowstyle hidden -command "Start-Process cmd -ArgumentList '/s,/c
		$a_00_2 = {3a 00 2f 00 2f 00 61 00 72 00 6b 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 2e 00 6d 00 73 00 69 00 } //3 ://arkupdate.com/download/installer.msi
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*3) >=5
 
}