
rule Trojan_Win32_KillMBR_AC_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 "
		
	strings :
		$a_01_0 = {57 72 69 74 65 46 69 6c 65 } //1 WriteFile
		$a_01_1 = {43 72 65 61 74 65 46 69 6c 65 57 } //1 CreateFileW
		$a_01_2 = {43 6c 6f 73 65 48 61 6e 64 6c 65 } //1 CloseHandle
		$a_01_3 = {5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 30 00 } //2 \.\PhysicalDrive0
		$a_01_4 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 6f 62 6c 69 74 65 72 61 74 65 64 20 79 61 20 6d 75 6d } //2 Successfully obliterated ya mum
		$a_01_5 = {59 61 20 6d 75 6d 20 74 6f 6f 20 73 74 72 6f 6e 67 20 6d 61 74 65 } //2 Ya mum too strong mate
		$a_01_6 = {5c 52 65 6c 65 61 73 65 5c 4f 76 65 72 77 72 69 74 65 2e 70 64 62 } //2 \Release\Overwrite.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=11
 
}