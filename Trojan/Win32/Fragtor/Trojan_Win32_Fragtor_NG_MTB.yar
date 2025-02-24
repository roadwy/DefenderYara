
rule Trojan_Win32_Fragtor_NG_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 89 45 bb 88 45 bd 66 89 45 be 88 45 c0 66 89 45 c1 88 45 c3 66 89 45 c4 88 45 c6 66 89 45 c7 88 45 c9 66 89 45 ca 88 45 cc 89 45 b4 89 45 fc } //10
		$a_81_1 = {5f 70 63 72 65 5f } //1 _pcre_
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*1) >=11
 
}
rule Trojan_Win32_Fragtor_NG_MTB_2{
	meta:
		description = "Trojan:Win32/Fragtor.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {89 4d fc 8b 45 fc 8b 4d 08 89 08 8b 55 fc 83 3a 00 75 0c 6a 0c e8 62 9a 04 00 83 c4 04 eb 1f 8b 45 fc 83 38 04 7d 17 8b 4d fc 8b 11 6b d2 18 } //3
		$a_01_1 = {62 00 69 00 74 00 6a 00 6f 00 6b 00 65 00 72 00 32 00 30 00 32 00 34 00 2e 00 30 00 30 00 30 00 77 00 65 00 62 00 68 00 6f 00 73 00 74 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 } //1 bitjoker2024.000webhostapp.com
		$a_01_2 = {52 00 65 00 6d 00 6f 00 74 00 65 00 49 00 6e 00 6a 00 65 00 63 00 74 00 } //1 RemoteInject
		$a_01_3 = {54 00 72 00 6f 00 6a 00 61 00 6e 00 45 00 76 00 65 00 6e 00 74 00 } //1 TrojanEvent
		$a_01_4 = {54 00 6f 00 6e 00 67 00 78 00 69 00 6e 00 50 00 72 00 6f 00 63 00 } //1 TongxinProc
		$a_01_5 = {4b 00 69 00 6c 00 6c 00 43 00 6d 00 64 00 45 00 78 00 65 00 } //1 KillCmdExe
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}