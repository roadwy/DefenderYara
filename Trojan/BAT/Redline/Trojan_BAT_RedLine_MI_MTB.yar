
rule Trojan_BAT_RedLine_MI_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {09 03 16 03 8e 69 28 9b 01 00 06 2a 0a 38 65 ff ff ff 0b 38 6d ff ff ff 0c 2b 92 } //5
		$a_01_1 = {57 dd a2 2b 09 0f 00 00 00 d8 00 23 00 06 00 00 01 00 00 00 84 00 00 00 92 00 00 00 72 01 00 00 c6 } //5
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}
rule Trojan_BAT_RedLine_MI_MTB_2{
	meta:
		description = "Trojan:BAT/RedLine.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 d5 02 fc 09 0e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 3d 00 00 00 11 00 00 00 34 } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_3 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //1 HttpWebRequest
		$a_01_4 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_5 = {73 65 74 5f 55 73 65 72 41 67 65 6e 74 } //1 set_UserAgent
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}
rule Trojan_BAT_RedLine_MI_MTB_3{
	meta:
		description = "Trojan:BAT/RedLine.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 00 61 00 63 00 65 00 6b 00 2e 00 65 00 78 00 65 00 } //5 Hacek.exe
		$a_01_1 = {47 61 74 65 77 61 79 49 50 41 64 64 72 65 73 73 49 6e 66 6f 72 6d 61 74 69 6f 6e 43 6f 6c 6c 65 63 74 69 6f 6e } //1 GatewayIPAddressInformationCollection
		$a_01_2 = {47 65 74 44 65 66 61 75 6c 74 49 50 76 34 41 64 64 72 65 73 73 } //1 GetDefaultIPv4Address
		$a_01_3 = {43 61 70 74 75 72 65 } //1 Capture
		$a_01_4 = {42 43 52 59 50 54 5f 41 55 54 48 45 4e 54 49 43 41 54 45 44 5f 43 49 50 48 45 52 5f 4d 4f 44 45 5f 49 4e 46 4f } //1 BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}