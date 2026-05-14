
rule Trojan_BAT_PureRat_AH_MTB{
	meta:
		description = "Trojan:BAT/PureRat.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 0a 00 00 "
		
	strings :
		$a_03_0 = {05 00 04 7b ?? 05 00 04 61 28 b1 0a 00 06 28 } //6
		$a_03_1 = {05 00 04 7b ?? 05 00 04 61 28 ab 0a 00 06 20 } //6
		$a_81_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //2 CreateDecryptor
		$a_81_3 = {47 5a 69 70 53 74 72 65 61 6d } //2 GZipStream
		$a_81_4 = {53 79 73 74 65 6d 2e 4e 65 74 2e 53 6f 63 6b 65 74 73 } //2 System.Net.Sockets
		$a_81_5 = {50 72 6f 74 6f 42 75 66 2e 53 65 72 69 61 6c 69 7a 65 72 73 2e 49 50 72 6f 74 6f 53 65 72 69 61 6c 69 7a 65 72 2e 57 72 69 74 65 } //2 ProtoBuf.Serializers.IProtoSerializer.Write
		$a_81_6 = {50 72 6f 74 6f 42 75 66 2e 53 65 72 69 61 6c 69 7a 65 72 73 2e 49 50 72 6f 74 6f 54 79 70 65 53 65 72 69 61 6c 69 7a 65 72 2e 48 61 73 43 61 6c 6c 62 61 63 6b 73 } //2 ProtoBuf.Serializers.IProtoTypeSerializer.HasCallbacks
		$a_81_7 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //2 FromBase64String
		$a_81_8 = {4d 69 63 72 6f 73 6f 66 74 2e 43 6f 64 65 41 6e 61 6c 79 73 69 73 } //2 Microsoft.CodeAnalysis
		$a_81_9 = {57 72 69 74 65 50 61 63 6b 65 64 } //2 WritePacked
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*6+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2+(#a_81_5  & 1)*2+(#a_81_6  & 1)*2+(#a_81_7  & 1)*2+(#a_81_8  & 1)*2+(#a_81_9  & 1)*2) >=22
 
}