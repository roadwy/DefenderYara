
rule Trojan_Win32_NanoBot_SMW_MTB{
	meta:
		description = "Trojan:Win32/NanoBot.SMW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {8d 94 0d 00 fe ff ff 0f b6 34 10 0f b6 12 33 db 3b f2 74 0e 43 8b fe 33 fb 3b fa 75 f7 bf ff 01 00 00 89 9c 8d 04 f6 ff ff 41 3b cf } //2
		$a_81_1 = {6f 59 76 65 73 52 4b 47 73 79 2e 65 78 65 } //1 oYvesRKGsy.exe
		$a_81_2 = {4d 6e 52 70 65 78 6a 78 75 70 2e 76 62 73 } //1 MnRpexjxup.vbs
		$a_81_3 = {58 62 4c 41 42 74 6f 4b 4f 64 2e 6c 6e 6b } //1 XbLABtoKOd.lnk
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}