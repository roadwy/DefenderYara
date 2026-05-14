
rule Trojan_BAT_PureRat_AJ_MTB{
	meta:
		description = "Trojan:BAT/PureRat.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 0c 00 00 "
		
	strings :
		$a_01_0 = {06 2a 00 00 2e 28 23 0b 00 06 28 01 00 00 06 2a 13 30 04 00 9a 00 00 00 01 00 00 11 20 } //6
		$a_01_1 = {28 25 0a 00 06 28 01 00 00 06 2a ae 7e } //6
		$a_81_2 = {6d 38 44 45 } //5 m8DE
		$a_81_3 = {50 75 72 65 48 56 4e 43 5f 4c 69 62 2e } //5 PureHVNC_Lib.
		$a_81_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //2 CreateDecryptor
		$a_81_5 = {47 5a 69 70 53 74 72 65 61 6d } //2 GZipStream
		$a_81_6 = {53 79 73 74 65 6d 2e 4e 65 74 2e 53 6f 63 6b 65 74 73 } //2 System.Net.Sockets
		$a_81_7 = {50 72 6f 74 6f 42 75 66 2e 53 65 72 69 61 6c 69 7a 65 72 73 2e 49 50 72 6f 74 6f 53 65 72 69 61 6c 69 7a 65 72 2e 57 72 69 74 65 } //2 ProtoBuf.Serializers.IProtoSerializer.Write
		$a_81_8 = {50 72 6f 74 6f 42 75 66 2e 53 65 72 69 61 6c 69 7a 65 72 73 2e 49 50 72 6f 74 6f 54 79 70 65 53 65 72 69 61 6c 69 7a 65 72 2e 48 61 73 43 61 6c 6c 62 61 63 6b 73 } //2 ProtoBuf.Serializers.IProtoTypeSerializer.HasCallbacks
		$a_81_9 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //2 FromBase64String
		$a_81_10 = {4d 69 63 72 6f 73 6f 66 74 2e 43 6f 64 65 41 6e 61 6c 79 73 69 73 } //2 Microsoft.CodeAnalysis
		$a_81_11 = {57 72 69 74 65 50 61 63 6b 65 64 } //2 WritePacked
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*6+(#a_81_2  & 1)*5+(#a_81_3  & 1)*5+(#a_81_4  & 1)*2+(#a_81_5  & 1)*2+(#a_81_6  & 1)*2+(#a_81_7  & 1)*2+(#a_81_8  & 1)*2+(#a_81_9  & 1)*2+(#a_81_10  & 1)*2+(#a_81_11  & 1)*2) >=27
 
}