
rule Ransom_Win32_Akira_A_ibt{
	meta:
		description = "Ransom:Win32/Akira.A!ibt,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 "
		
	strings :
		$a_80_0 = {74 68 65 20 69 6e 74 65 72 6e 61 6c 20 69 6e 66 72 61 73 74 72 75 63 74 75 72 65 20 6f 66 20 79 6f 75 72 20 63 6f 6d 70 61 6e 79 20 69 73 20 66 75 6c 6c 79 20 6f 72 20 70 61 72 74 69 61 6c 6c 79 20 64 65 61 64 2c 20 61 6c 6c 20 79 6f 75 72 20 62 61 63 6b 75 70 73 } //the internal infrastructure of your company is fully or partially dead, all your backups  10
		$a_00_1 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } //1 -----BEGIN PUBLIC KEY-----
		$a_80_2 = {4b 65 65 70 20 69 6e 20 6d 69 6e 64 20 74 68 61 74 20 74 68 65 20 66 61 73 74 65 72 20 79 6f 75 20 77 69 6c 6c 20 67 65 74 20 69 6e 20 74 6f 75 63 68 2c 20 74 68 65 20 6c 65 73 73 20 64 61 6d 61 67 65 20 77 65 20 63 61 75 73 65 2e } //Keep in mind that the faster you will get in touch, the less damage we cause.  1
		$a_80_3 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 43 6f 6d 6d 61 6e 64 20 22 47 65 74 2d 57 6d 69 4f 62 6a 65 63 74 20 57 69 6e 33 32 5f 53 68 61 64 6f 77 63 6f 70 79 20 7c 20 52 65 6d 6f 76 65 2d 57 6d 69 4f 62 6a 65 63 74 22 } //powershell.exe -Command "Get-WmiObject Win32_Shadowcopy | Remove-WmiObject"  1
		$a_00_4 = {44 3a 5c 76 63 70 72 6f 6a 65 63 74 73 5c 61 6b 69 72 61 5c 61 73 69 6f } //1 D:\vcprojects\akira\asio
		$a_03_5 = {68 74 74 70 73 3a 2f 2f 61 6b 69 72 61 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-15] 2e 6f 6e 69 6f 6e } //1
	condition:
		((#a_80_0  & 1)*10+(#a_00_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_00_4  & 1)*1+(#a_03_5  & 1)*1) >=11
 
}