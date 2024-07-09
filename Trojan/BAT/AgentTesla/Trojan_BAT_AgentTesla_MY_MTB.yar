
rule Trojan_BAT_AgentTesla_MY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b [0-07] 11 04 08 8e 69 5d 91 06 11 04 91 61 d2 [0-12] 17 58 13 04 11 04 06 8e 69 32 ?? 09 2a } //10
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_2 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_3 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}
rule Trojan_BAT_AgentTesla_MY_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 16 00 00 "
		
	strings :
		$a_80_0 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //VirtualProtect  1
		$a_80_1 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c } //kernel32.dll  1
		$a_80_2 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //CheckRemoteDebuggerPresent  1
		$a_80_3 = {52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //ResourceManager  1
		$a_80_4 = {69 6e 76 6f 69 63 65 } //invoice  1
		$a_80_5 = {70 61 73 73 77 6f 72 64 } //password  1
		$a_80_6 = {48 6f 74 65 6c 4d 67 6d 74 53 79 73 74 65 6d 2e 42 6f 6f 6b 69 6e 67 2e 72 65 73 6f 75 72 63 65 73 } //HotelMgmtSystem.Booking.resources  1
		$a_80_7 = {48 6f 74 65 6c 4d 67 6d 74 53 79 73 74 65 6d 2e 6c 6f 67 69 6e 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //HotelMgmtSystem.loginForm.resources  1
		$a_80_8 = {48 6f 74 65 6c 4d 67 6d 74 53 79 73 74 65 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //HotelMgmtSystem.Properties.Resources.resources  1
		$a_00_9 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_00_10 = {52 65 61 64 42 79 74 65 } //1 ReadByte
		$a_00_11 = {67 65 74 5f 4c 65 6e 67 74 68 } //1 get_Length
		$a_80_12 = {42 75 66 66 65 72 } //Buffer  1
		$a_80_13 = {42 6c 6f 63 6b 43 6f 70 79 } //BlockCopy  1
		$a_80_14 = {45 6e 63 6f 64 69 6e 67 } //Encoding  1
		$a_80_15 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //get_Assembly  1
		$a_80_16 = {53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 2e 42 69 74 6d 61 70 } //System.Drawing.Bitmap  1
		$a_80_17 = {47 65 74 54 79 70 65 73 } //GetTypes  1
		$a_80_18 = {47 65 74 4d 65 74 68 6f 64 73 } //GetMethods  1
		$a_80_19 = {4d 65 74 68 6f 64 42 61 73 65 } //MethodBase  1
		$a_80_20 = {49 6e 76 6f 6b 65 } //Invoke  1
		$a_80_21 = {43 6f 6d 70 6f 6e 65 6e 74 52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //ComponentResourceManager  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1+(#a_80_15  & 1)*1+(#a_80_16  & 1)*1+(#a_80_17  & 1)*1+(#a_80_18  & 1)*1+(#a_80_19  & 1)*1+(#a_80_20  & 1)*1+(#a_80_21  & 1)*1) >=20
 
}