
rule Trojan_BAT_AgentTesla_ANV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ANV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {d4 91 11 04 11 04 07 95 11 04 08 95 58 20 ff 00 00 00 5f 95 61 ?? ?? ?? ?? ?? 9c 00 11 08 17 6a 58 13 08 11 08 11 05 8e 69 17 59 6a fe 02 16 fe 01 13 09 11 09 2d 97 } //10
		$a_80_1 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  2
		$a_80_2 = {47 65 74 54 79 70 65 } //GetType  2
		$a_80_3 = {49 6e 76 6f 6b 65 } //Invoke  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=16
 
}
rule Trojan_BAT_AgentTesla_ANV_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ANV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {24 35 35 65 63 31 61 65 38 2d 34 66 62 39 2d 34 34 64 61 2d 39 65 65 30 2d 38 35 39 34 66 63 64 31 36 62 34 35 } //1 $55ec1ae8-4fb9-44da-9ee0-8594fcd16b45
		$a_81_1 = {44 37 4a 34 38 48 37 37 46 39 59 35 35 4b 34 4a 43 41 47 35 46 44 } //1 D7J48H77F9Y55K4JCAG5FD
		$a_81_2 = {4d 75 6c 74 69 70 6c 61 79 65 72 4c 69 62 2e 52 65 73 6f 75 72 63 65 31 2e 72 65 73 6f 75 72 63 65 73 } //1 MultiplayerLib.Resource1.resources
		$a_81_3 = {4d 75 6c 74 69 70 6c 61 79 65 72 4c 69 62 2e 53 65 72 76 65 72 57 69 6e 64 6f 77 2e 72 65 73 6f 75 72 63 65 73 } //1 MultiplayerLib.ServerWindow.resources
		$a_81_4 = {53 6d 61 72 74 46 6f 72 6d 61 74 2e 53 6d 61 72 74 45 78 74 65 6e 73 69 6f 6e 73 } //1 SmartFormat.SmartExtensions
		$a_81_5 = {4f 66 66 73 65 74 4d 61 72 73 68 61 6c 65 72 } //1 OffsetMarshaler
		$a_81_6 = {52 65 74 75 72 6e 4d 65 73 73 61 67 65 } //1 ReturnMessage
		$a_81_7 = {42 61 63 6b 67 72 6f 75 6e 64 49 6d 61 67 65 } //1 BackgroundImage
		$a_81_8 = {41 61 61 61 61 61 72 67 68 21 20 53 65 72 76 65 72 } //1 Aaaaaargh! Server
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}