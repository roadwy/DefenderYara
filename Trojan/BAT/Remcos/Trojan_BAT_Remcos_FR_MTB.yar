
rule Trojan_BAT_Remcos_FR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.FR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 1b 00 7e ?? ?? ?? 04 06 7e ?? ?? ?? 04 06 91 20 a5 02 00 00 59 d2 9c 00 06 17 58 0a 06 7e ?? ?? ?? 04 8e 69 fe 04 0b 07 2d d7 } //1
		$a_81_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_3 = {41 57 58 41 57 46 57 41 32 } //1 AWXAWFWA2
		$a_81_4 = {53 41 46 46 57 41 46 32 } //1 SAFFWAF2
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_BAT_Remcos_FR_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.FR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 15 00 00 "
		
	strings :
		$a_81_0 = {44 6f 63 6b 53 74 79 6c 65 } //1 DockStyle
		$a_81_1 = {73 65 74 5f 53 65 72 76 69 63 65 4e 61 6d 65 } //1 set_ServiceName
		$a_81_2 = {45 6e 63 6f 64 65 4e 65 74 62 69 6f 73 4e 61 6d 65 } //1 EncodeNetbiosName
		$a_81_3 = {50 61 63 6b 65 74 4d 61 74 63 68 } //1 PacketMatch
		$a_81_4 = {43 6f 6d 70 75 74 65 48 61 73 68 } //1 ComputeHash
		$a_81_5 = {70 61 63 6b 65 74 48 65 61 64 65 72 } //1 packetHeader
		$a_81_6 = {52 43 32 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 RC2CryptoServiceProvider
		$a_81_7 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 MD5CryptoServiceProvider
		$a_81_8 = {53 74 72 69 6e 67 42 75 69 6c 64 65 72 } //1 StringBuilder
		$a_81_9 = {4e 65 74 77 6f 72 6b 54 6f 48 6f 73 74 4f 72 64 65 72 } //1 NetworkToHostOrder
		$a_81_10 = {57 65 62 42 72 6f 77 73 65 72 } //1 WebBrowser
		$a_81_11 = {42 69 74 43 6f 6e 76 65 72 74 65 72 } //1 BitConverter
		$a_81_12 = {67 65 74 5f 45 6d 61 69 6c 53 65 72 76 65 72 } //1 get_EmailServer
		$a_81_13 = {5f 65 6d 61 69 6c 53 65 72 76 65 72 } //1 _emailServer
		$a_81_14 = {47 65 74 41 6c 6c 4e 65 74 77 6f 72 6b 49 6e 74 65 72 66 61 63 65 73 } //1 GetAllNetworkInterfaces
		$a_81_15 = {47 65 74 50 68 79 73 69 63 61 6c 41 64 64 72 65 73 73 } //1 GetPhysicalAddress
		$a_81_16 = {52 43 32 44 65 63 72 79 70 74 } //1 RC2Decrypt
		$a_81_17 = {54 68 72 65 61 64 53 74 61 72 74 } //1 ThreadStart
		$a_81_18 = {53 65 6e 64 4e 65 74 62 69 6f 73 51 75 65 72 79 } //1 SendNetbiosQuery
		$a_81_19 = {56 4d 77 61 72 65 20 56 69 72 74 75 61 6c 20 45 74 68 65 72 6e 65 74 20 41 64 61 70 74 65 72 } //1 VMware Virtual Ethernet Adapter
		$a_81_20 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*1+(#a_81_17  & 1)*1+(#a_81_18  & 1)*1+(#a_81_19  & 1)*1+(#a_81_20  & 1)*1) >=21
 
}