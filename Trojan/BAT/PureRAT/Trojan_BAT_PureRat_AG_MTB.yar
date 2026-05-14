
rule Trojan_BAT_PureRat_AG_MTB{
	meta:
		description = "Trojan:BAT/PureRat.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 "
		
	strings :
		$a_81_0 = {53 79 73 74 65 6d 2e 43 6f 6c 6c 65 63 74 69 6f 6e 73 2e 47 65 6e 65 72 69 63 2e 49 45 6e 75 6d 65 72 61 74 6f 72 3c 50 75 72 65 48 56 4e 43 5f 4c 69 62 2e 50 61 63 6b 65 74 73 2e 46 69 6c 65 4d 61 6e 61 67 65 72 2e 54 72 61 6e 73 66 65 72 50 61 63 6b 3e 2e 67 65 74 5f 43 75 72 72 65 6e 74 } //2 System.Collections.Generic.IEnumerator<PureHVNC_Lib.Packets.FileManager.TransferPack>.get_Current
		$a_81_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //2 CreateDecryptor
		$a_81_2 = {47 5a 69 70 53 74 72 65 61 6d } //2 GZipStream
		$a_81_3 = {53 79 73 74 65 6d 2e 4e 65 74 2e 53 6f 63 6b 65 74 73 } //2 System.Net.Sockets
		$a_81_4 = {50 72 6f 74 6f 42 75 66 2e 53 65 72 69 61 6c 69 7a 65 72 73 2e 49 50 72 6f 74 6f 53 65 72 69 61 6c 69 7a 65 72 2e 57 72 69 74 65 } //2 ProtoBuf.Serializers.IProtoSerializer.Write
		$a_81_5 = {50 72 6f 74 6f 42 75 66 2e 53 65 72 69 61 6c 69 7a 65 72 73 2e 49 50 72 6f 74 6f 54 79 70 65 53 65 72 69 61 6c 69 7a 65 72 2e 48 61 73 43 61 6c 6c 62 61 63 6b 73 } //2 ProtoBuf.Serializers.IProtoTypeSerializer.HasCallbacks
		$a_81_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //2 FromBase64String
		$a_81_7 = {4d 69 63 72 6f 73 6f 66 74 2e 43 6f 64 65 41 6e 61 6c 79 73 69 73 } //2 Microsoft.CodeAnalysis
		$a_81_8 = {57 72 69 74 65 50 61 63 6b 65 64 } //2 WritePacked
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2+(#a_81_5  & 1)*2+(#a_81_6  & 1)*2+(#a_81_7  & 1)*2+(#a_81_8  & 1)*2) >=18
 
}