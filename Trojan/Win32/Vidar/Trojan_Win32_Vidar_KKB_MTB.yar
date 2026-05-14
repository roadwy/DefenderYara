
rule Trojan_Win32_Vidar_KKB_MTB{
	meta:
		description = "Trojan:Win32/Vidar.KKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,26 00 26 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 8b 94 24 48 04 00 00 48 ff c2 4c 8b 84 24 70 04 00 00 4c 8b 8c 24 90 05 00 00 48 89 d9 48 89 c3 48 89 d0 4c 89 ca } //20
		$a_03_1 = {48 89 ca 48 81 e2 ?? ?? ?? ?? 48 89 ce 48 29 d6 40 88 74 0c 30 48 ff c1 } //10
		$a_01_2 = {48 8d 1c 02 48 8b 74 24 68 48 01 d6 0f b6 36 40 88 33 48 ff c2 } //5
		$a_01_3 = {6d 61 69 6e 2e 47 65 74 49 6e 73 74 61 6c 6c 44 65 74 61 69 6c 73 50 61 79 6c 6f 61 64 } //3 main.GetInstallDetailsPayload
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*3) >=38
 
}