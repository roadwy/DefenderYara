
rule Trojan_BAT_Polazert_ADF_MTB{
	meta:
		description = "Trojan:BAT/Polazert.ADF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 07 00 00 "
		
	strings :
		$a_00_0 = {16 0c 16 0d 2b 27 00 07 08 07 08 91 06 09 91 61 d2 9c 09 17 58 06 8e 69 fe 04 13 05 11 05 2d 04 16 0d 2b 04 09 17 58 0d 08 17 58 0c 00 08 07 8e 69 fe 04 13 05 11 05 2d cd } //11
		$a_80_1 = {57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d 2e 4e 61 6d 65 3d 27 7b 30 7d 27 } //Win32_ComputerSystem.Name='{0}'  5
		$a_80_2 = {49 73 41 64 6d 69 6e } //IsAdmin  2
		$a_80_3 = {47 65 74 57 69 6e 56 65 72 73 69 6f 6e } //GetWinVersion  2
		$a_80_4 = {47 65 74 55 73 65 72 4e 61 6d 65 } //GetUserName  2
		$a_80_5 = {47 65 74 43 6f 6d 70 75 74 65 72 4e 61 6d 65 } //GetComputerName  2
		$a_80_6 = {45 6e 63 72 79 70 74 58 6f 72 } //EncryptXor  2
	condition:
		((#a_00_0  & 1)*11+(#a_80_1  & 1)*5+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2) >=26
 
}