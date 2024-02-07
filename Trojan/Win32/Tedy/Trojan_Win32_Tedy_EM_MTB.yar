
rule Trojan_Win32_Tedy_EM_MTB{
	meta:
		description = "Trojan:Win32/Tedy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 53 69 72 4c 65 6e 6e 6f 78 } //01 00  C:\Users\SirLennox
		$a_01_1 = {52 65 6c 65 61 73 65 5c 4e 65 6b 6f 49 6e 73 74 61 6c 6c 65 72 2e 70 64 62 } //01 00  Release\NekoInstaller.pdb
		$a_01_2 = {5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 48 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //01 00  \ServiceHost.exe
		$a_01_3 = {6e 00 65 00 6b 00 6f 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 } //01 00  nekoservice
		$a_01_4 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 57 } //00 00  CreateDirectoryW
	condition:
		any of ($a_*)
 
}