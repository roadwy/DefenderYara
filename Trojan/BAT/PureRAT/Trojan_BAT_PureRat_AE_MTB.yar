
rule Trojan_BAT_PureRat_AE_MTB{
	meta:
		description = "Trojan:BAT/PureRat.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 "
		
	strings :
		$a_81_0 = {3c 4d 6f 64 75 6c 65 3e 7b 30 62 39 35 39 61 63 39 2d 63 34 37 32 2d 34 30 37 62 2d 38 37 30 66 2d 36 62 31 61 35 64 33 65 31 64 62 32 7d } //2 <Module>{0b959ac9-c472-407b-870f-6b1a5d3e1db2}
		$a_81_1 = {50 72 6f 74 6f 42 75 66 2e 53 65 72 69 61 6c 69 7a 65 72 73 2e 49 50 72 6f 74 6f 54 79 70 65 53 65 72 69 61 6c 69 7a 65 72 2e 48 61 73 43 61 6c 6c 62 61 63 6b 73 } //2 ProtoBuf.Serializers.IProtoTypeSerializer.HasCallbacks
		$a_81_2 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e } //2 System.Reflection
		$a_81_3 = {50 75 72 65 48 56 4e 43 5f 4c 69 62 2e 4e 65 74 77 6f 72 6b 69 6e 67 } //2 PureHVNC_Lib.Networking
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_5 = {4d 69 63 72 6f 73 6f 66 74 2e 43 6f 64 65 41 6e 61 6c 79 73 69 73 } //1 Microsoft.CodeAnalysis
		$a_81_6 = {57 72 69 74 65 50 61 63 6b 65 64 } //1 WritePacked
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=11
 
}