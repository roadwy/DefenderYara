
rule Trojan_BAT_FileCoder_ARAX_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_80_0 = {63 6c 69 70 70 79 5f 72 61 6e 73 6f 6d 77 61 72 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //clippy_ransomware.Properties.Resources  2
		$a_80_1 = {65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //encrypted files  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}
rule Trojan_BAT_FileCoder_ARAX_MTB_2{
	meta:
		description = "Trojan:BAT/FileCoder.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 61 6e 73 6f 6d 77 61 72 65 50 4f 43 } //2 RansomwarePOC
		$a_01_1 = {65 6e 63 72 79 70 74 46 6f 6c 64 65 72 43 6f 6e 74 65 6e 74 73 } //2 encryptFolderContents
		$a_01_2 = {64 72 6f 70 52 61 6e 73 6f 6d 4c 65 74 74 65 72 } //2 dropRansomLetter
		$a_01_3 = {74 78 74 42 69 74 63 6f 69 6e 41 64 64 72 65 73 73 } //2 txtBitcoinAddress
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}
rule Trojan_BAT_FileCoder_ARAX_MTB_3{
	meta:
		description = "Trojan:BAT/FileCoder.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 07 00 00 "
		
	strings :
		$a_01_0 = {45 6e 63 72 79 70 74 46 69 6c 65 } //6 EncryptFile
		$a_01_1 = {44 69 73 61 62 6c 65 43 6f 6e 74 72 6f 6c 50 61 6e 65 6c } //1 DisableControlPanel
		$a_01_2 = {44 69 73 61 62 6c 65 50 6f 77 65 72 73 68 65 6c 6c } //1 DisablePowershell
		$a_00_3 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 52 00 75 00 6e 00 } //1 DisableRun
		$a_00_4 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //1 DisableTaskMgr
		$a_00_5 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 54 00 6f 00 6f 00 6c 00 73 00 } //1 DisableRegistryTools
		$a_00_6 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 43 00 4d 00 44 00 } //1 DisableCMD
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=12
 
}