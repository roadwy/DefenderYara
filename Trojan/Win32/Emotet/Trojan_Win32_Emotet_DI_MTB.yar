
rule Trojan_Win32_Emotet_DI_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b 0f 8d 7f 04 33 cb 0f b6 c1 66 89 02 8b c1 c1 e8 08 8d 52 08 0f b6 c0 66 89 42 fa c1 e9 10 0f b6 c1 c1 e9 08 45 66 89 42 fc 0f b6 c1 66 89 42 fe 3b ee 72 } //1
		$a_00_1 = {8b 45 3c 8b 5c 24 10 89 44 24 28 8b 7c 28 78 03 fd 8b 47 1c 8b 4f 20 03 c5 89 44 24 24 03 cd 8b 47 24 03 c5 89 4c 24 1c 89 44 24 20 eb } //1
		$a_81_2 = {43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c } //1 Control_RunDLL
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}