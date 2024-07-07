
rule Trojan_MacOS_DaclsRAT_A_dha{
	meta:
		description = "Trojan:MacOS/DaclsRAT.A!dha,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {55 48 89 e5 41 57 41 56 41 54 53 48 81 ec 30 04 00 00 49 89 f7 49 89 fe 48 8b 05 09 31 08 00 48 8b 00 48 89 45 d8 48 8d 35 e3 56 08 00 ba 0c 00 00 00 e8 a9 bb ff ff 85 c0 0f 84 a6 01 00 00 8b 1d cf 56 08 00 81 fb f8 3f 00 00 0f 87 94 01 00 00 89 1d c5 56 08 00 4c 8b 25 c2 56 08 00 be 00 40 00 00 4c 89 e7 e8 63 ff 06 00 } //2
		$a_00_1 = {48 89 e5 41 57 41 56 53 50 49 89 d7 48 89 f3 49 89 fe e8 14 05 07 00 85 c0 74 15 b9 ff ff ff ff 0f 4f c8 89 c8 48 83 c4 08 5b 41 5e 41 5f 5d c3 } //1
		$a_00_2 = {2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 44 61 65 6d 6f 6e 73 2f 63 6f 6d 2e 61 65 78 2d 6c 6f 6f 70 2e 61 67 65 6e 74 2e 70 6c 69 73 74 } //1 /Library/LaunchDaemons/com.aex-loop.agent.plist
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}