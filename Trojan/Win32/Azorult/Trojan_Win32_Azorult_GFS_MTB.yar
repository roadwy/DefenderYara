
rule Trojan_Win32_Azorult_GFS_MTB{
	meta:
		description = "Trojan:Win32/Azorult.GFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {72 65 69 75 64 78 61 6d 63 73 79 75 61 73 64 78 2e 65 78 65 } //reiudxamcsyuasdx.exe  1
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_2 = {43 72 79 70 74 44 65 63 72 79 70 74 } //1 CryptDecrypt
		$a_01_3 = {6f 6d 65 66 6e 73 78 73 64 63 77 61 79 } //1 omefnsxsdcway
		$a_01_4 = {6e 61 76 65 66 6b 64 65 65 63 73 66 77 } //1 navefkdeecsfw
		$a_01_5 = {6d 6b 73 61 6d 66 65 73 61 73 66 } //1 mksamfesasf
		$a_01_6 = {61 6d 76 73 69 76 6d 65 6f 66 6a 63 73 } //1 amvsivmeofjcs
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}