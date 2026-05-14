
rule Trojan_BAT_ValleyRAT_GZD_MTB{
	meta:
		description = "Trojan:BAT/ValleyRAT.GZD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {36 42 35 32 34 35 31 31 2d 34 37 39 45 2d 42 43 35 45 2d 39 45 31 31 2d 39 45 44 44 32 36 32 41 45 32 43 45 } //2 6B524511-479E-BC5E-9E11-9EDD262AE2CE
		$a_01_1 = {4d 69 63 72 6f 73 6f 66 74 2e 43 6f 64 65 41 6e 61 6c 79 73 69 73 } //1 Microsoft.CodeAnalysis
		$a_01_2 = {57 72 69 74 65 50 61 63 6b 65 64 } //1 WritePacked
		$a_01_3 = {48 61 73 43 61 6c 6c 62 61 63 6b 73 } //1 HasCallbacks
		$a_01_4 = {50 72 6f 74 6f 42 75 66 2e 53 65 72 69 61 6c 69 7a 65 72 73 2e 49 50 72 6f 74 6f 54 79 70 65 53 65 72 69 61 6c 69 7a 65 72 2e 48 61 73 43 61 6c 6c 62 61 63 6b 73 } //1 ProtoBuf.Serializers.IProtoTypeSerializer.HasCallbacks
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}