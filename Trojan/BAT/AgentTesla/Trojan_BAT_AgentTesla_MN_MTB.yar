
rule Trojan_BAT_AgentTesla_MN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {0d 14 13 04 00 72 90 01 03 70 28 90 01 03 0a 13 05 11 05 14 fe 03 13 06 11 06 2c 5f 00 11 05 6f 90 01 03 0a 13 04 11 04 14 fe 03 13 07 11 07 2c 49 00 11 04 6f 90 01 03 0a 0c 73 90 01 03 0a 0d 20 00 04 00 00 8d 90 01 01 00 00 01 13 08 00 08 11 08 16 11 08 8e 69 6f 90 01 03 0a 13 09 09 11 08 16 11 09 6f 90 01 03 0a 00 07 11 09 58 0b 00 11 09 16 fe 02 13 0a 11 0a 2d 90 00 } //1
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_2 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_4 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_6 = {45 78 63 65 70 74 69 6f 6e } //1 Exception
		$a_01_7 = {57 65 62 52 65 71 75 65 73 74 } //1 WebRequest
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule Trojan_BAT_AgentTesla_MN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0f 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 44 41 54 41 42 41 53 45 20 41 51 55 49 2f 64 64 6f 73 2e 74 78 74 } //http://DATABASE AQUI/ddos.txt  1
		$a_80_1 = {68 74 74 70 3a 2f 2f 44 41 54 41 42 41 53 45 20 41 51 55 49 2f 67 65 6f 69 70 2e 74 78 74 } //http://DATABASE AQUI/geoip.txt  1
		$a_80_2 = {68 74 74 70 3a 2f 2f 44 41 54 41 42 41 53 45 20 41 51 55 49 2f 73 6e 69 66 66 65 72 2e 74 78 74 } //http://DATABASE AQUI/sniffer.txt  1
		$a_80_3 = {68 74 74 70 3a 2f 2f 44 41 54 41 42 41 53 45 20 41 51 55 49 2f 64 61 74 61 62 61 73 65 2e 74 78 74 } //http://DATABASE AQUI/database.txt  1
		$a_80_4 = {68 74 74 70 3a 2f 2f 44 41 54 41 42 41 53 45 20 41 51 55 49 2f 63 68 61 74 2e 74 78 74 } //http://DATABASE AQUI/chat.txt  1
		$a_80_5 = {68 74 74 70 3a 2f 2f 44 41 54 41 42 41 53 45 20 41 51 55 49 2f 70 72 6f 6a 65 63 74 2e 74 78 74 } //http://DATABASE AQUI/project.txt  1
		$a_80_6 = {66 75 63 6b 69 6e 68 6f 6b 73 67 79 } //fuckinhoksgy  1
		$a_80_7 = {77 69 72 65 73 68 61 72 6b } //wireshark  1
		$a_80_8 = {53 6b 79 70 65 20 53 6e 69 66 66 65 72 } //Skype Sniffer  1
		$a_80_9 = {73 6e 69 66 66 65 72 73 74 61 74 75 73 } //snifferstatus  1
		$a_80_10 = {67 65 6f 69 70 73 74 61 74 75 73 } //geoipstatus  1
		$a_80_11 = {64 64 6f 73 73 74 61 74 75 73 } //ddosstatus  1
		$a_80_12 = {63 68 61 74 73 74 61 74 75 73 } //chatstatus  1
		$a_80_13 = {64 61 74 61 62 61 73 65 73 74 61 74 75 73 } //databasestatus  1
		$a_80_14 = {70 72 6f 6a 65 63 74 73 74 61 74 75 73 } //projectstatus  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1) >=10
 
}