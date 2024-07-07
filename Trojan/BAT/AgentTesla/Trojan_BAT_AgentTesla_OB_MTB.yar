
rule Trojan_BAT_AgentTesla_OB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {53 69 6d 70 6c 65 47 61 6d 65 4c 69 62 2e 57 6f 72 64 4a 75 6d 62 6c 65 50 72 6f 2e 72 65 73 6f 75 72 63 65 73 } //1 SimpleGameLib.WordJumblePro.resources
		$a_81_1 = {67 65 74 5f 78 78 78 78 78 78 } //1 get_xxxxxx
		$a_81_2 = {5f 69 73 44 65 66 65 6e 64 } //1 _isDefend
		$a_81_3 = {67 65 74 5f 4f 66 66 73 65 74 4d 61 72 73 68 61 6c 65 72 } //1 get_OffsetMarshaler
		$a_81_4 = {49 6e 69 74 69 61 6c 69 7a 65 41 72 72 61 79 } //1 InitializeArray
		$a_81_5 = {41 75 74 6f 53 63 61 6c 65 42 61 73 65 53 69 7a 65 } //1 AutoScaleBaseSize
		$a_81_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_7 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 } //1 CreateDirectory
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
rule Trojan_BAT_AgentTesla_OB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.OB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {f2 02 f4 02 0f 03 ef 02 3d 72 eb 02 3d 72 3d 72 e3 02 3d 72 3d 72 cd 02 cd 02 d6 02 3d 72 ea 02 05 03 3d 72 3d 72 3d 72 3d 72 df 02 ef } //1
		$a_01_1 = {d6 02 03 03 e6 02 d1 02 ef 02 0d 03 e2 02 ef 02 3d 72 e0 02 0e 03 15 03 0a 03 e4 02 16 03 e7 02 e4 02 e7 02 e7 02 09 03 3d 72 3d 72 05 03 d2 02 05 03 3d 72 df 02 e1 } //1
		$a_01_2 = {df 02 18 03 df 02 e1 02 d2 02 df 02 eb 02 3d 72 13 03 df 02 e2 02 3d 72 3d 72 3d 72 3d 72 3d 72 3d 72 3d 72 3d 72 3d 72 3d 72 3d 72 3d 72 } //1
		$a_80_3 = {42 23 75 6e 23 69 66 75 23 5f 54 65 78 23 74 42 6f 23 78 } //B#un#ifu#_Tex#tBo#x  1
		$a_80_4 = {23 47 65 74 23 4d 65 74 23 68 6f 64 } //#Get#Met#hod  1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}