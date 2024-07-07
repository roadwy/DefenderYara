
rule Trojan_Win32_Zbot_ABA_MTB{
	meta:
		description = "Trojan:Win32/Zbot.ABA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 75 fc 83 ee f1 f7 c6 66 9f 00 00 75 16 33 f3 ba 57 00 00 00 89 b5 44 ff ff ff 89 7d 90 89 95 58 ff ff ff 89 45 cc 5f 8b f7 89 b5 68 ff ff ff 5e f7 c6 87 00 00 00 75 15 33 c7 8b 8d 5c ff ff ff 89 4d e0 3b c7 75 06 } //10
		$a_80_1 = {63 6f 6d 73 76 63 73 2e 64 6c 6c } //comsvcs.dll  1
		$a_01_2 = {47 65 74 56 6f 6c 75 6d 65 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 GetVolumeInformation
		$a_01_3 = {51 75 65 72 79 44 6f 73 44 65 76 69 63 65 } //1 QueryDosDevice
		$a_01_4 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //1 LoadResource
	condition:
		((#a_01_0  & 1)*10+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}