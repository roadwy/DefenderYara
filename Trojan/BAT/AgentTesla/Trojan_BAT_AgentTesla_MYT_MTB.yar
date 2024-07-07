
rule Trojan_BAT_AgentTesla_MYT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MYT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0d 00 00 "
		
	strings :
		$a_80_0 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } //Create__Instance__  1
		$a_80_1 = {66 72 6d 4c 6f 67 69 6e } //frmLogin  1
		$a_80_2 = {41 73 79 6d 6d 65 74 72 69 63 } //Asymmetric  1
		$a_80_3 = {45 6e 76 6f 79 54 65 72 6d 69 6e 61 74 6f 72 53 69 6e 6b } //EnvoyTerminatorSink  1
		$a_80_4 = {44 65 73 74 69 6e 61 74 69 6f 6e 64 } //Destinationd  1
		$a_80_5 = {4d 65 74 61 64 61 74 61 43 6f 6c 6c 65 63 74 6f 72 } //MetadataCollector  1
		$a_80_6 = {50 6f 6f 6c 41 77 61 69 74 61 62 6c 65 } //PoolAwaitable  1
		$a_80_7 = {49 54 79 70 65 43 6f 6d 70 } //ITypeComp  1
		$a_80_8 = {4d 69 6e 6f 72 56 65 72 73 69 6f 6e } //MinorVersion  1
		$a_80_9 = {41 70 70 6c 69 63 61 74 69 6f 6e 49 64 65 6e 74 69 74 79 } //ApplicationIdentity  1
		$a_80_10 = {41 70 70 44 6f 6d 61 69 6e } //AppDomain  1
		$a_80_11 = {44 65 73 74 69 6e 61 74 69 6f 6e 64 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //Destinationd.Resources.resources  1
		$a_80_12 = {44 65 73 74 69 6e 61 74 69 6f 6e 64 2e 55 6e 64 65 72 6c 79 69 6e 67 2e 72 65 73 6f 75 72 63 65 73 } //Destinationd.Underlying.resources  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1) >=12
 
}