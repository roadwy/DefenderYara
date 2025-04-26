
rule Trojan_BAT_AgentTesla_OX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {11 05 16 9a 28 [0-04] d0 [0-04] 28 [0-04] 28 [0-04] 74 [0-07] 28 [0-07] 72 [0-04] 17 8d [0-07] 8c [0-04] a2 14 14 28 [0-04] 09 17 da 17 d6 8d [0-04] 13 04 07 14 72 [0-04] 19 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_OX_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.OX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_80_0 = {46 6f 75 72 41 72 } //FourAr  2
		$a_80_1 = {53 74 72 52 65 76 65 72 73 65 } //StrReverse  2
		$a_80_2 = {46 61 6c 6c 62 61 63 6b 42 75 66 66 65 72 } //FallbackBuffer  2
		$a_80_3 = {57 53 54 52 42 75 66 66 65 72 4d 61 72 73 68 61 6c 65 72 } //WSTRBufferMarshaler  2
		$a_80_4 = {47 65 74 54 79 70 65 } //GetType  2
		$a_80_5 = {53 61 66 65 52 65 67 69 73 74 72 79 48 61 6e 64 6c 65 2e 49 50 65 72 6d 69 73 73 69 6f 6e } //SafeRegistryHandle.IPermission  2
		$a_80_6 = {4c 6f 67 69 6e 46 6f 72 6d } //LoginForm  2
		$a_02_7 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 74 00 65 00 6d 00 70 00 75 00 72 00 69 00 2e 00 6f 00 72 00 67 00 2f 00 [0-25] 2e 00 78 00 73 00 64 00 } //2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2+(#a_02_7  & 1)*2) >=16
 
}