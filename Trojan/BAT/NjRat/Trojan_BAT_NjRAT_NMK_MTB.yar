
rule Trojan_BAT_NjRAT_NMK_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.NMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_81_0 = {46 75 63 6b 43 72 79 70 74 2e 52 65 73 6f 75 72 63 65 73 } //2 FuckCrypt.Resources
		$a_81_1 = {68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e } //1 https://pastebin.
		$a_81_2 = {63 79 62 65 72 2d 70 61 73 73 77 6f 72 64 2d 66 72 65 65 70 69 6b } //1 cyber-password-freepik
		$a_81_3 = {55 70 43 72 79 5c 6f 62 6a 5c 44 65 62 75 67 5c 46 75 63 6b 43 72 79 70 74 2e 70 64 62 } //1 UpCry\obj\Debug\FuckCrypt.pdb
		$a_81_4 = {41 74 69 20 56 6d 77 61 72 65 2c 20 56 69 72 74 75 61 6c 42 6f 78 } //1 Ati Vmware, VirtualBox
		$a_81_5 = {5b 73 79 73 74 65 6d 2e 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 [system.Convert]::FromBase64String
		$a_81_6 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 46 69 6c 65 } //1 powershell -ExecutionPolicy Bypass -File
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=8
 
}