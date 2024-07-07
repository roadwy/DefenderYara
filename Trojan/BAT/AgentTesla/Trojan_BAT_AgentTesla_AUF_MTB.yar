
rule Trojan_BAT_AgentTesla_AUF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AUF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_80_0 = {4e 65 77 74 6f 6e 73 6f 66 74 2e 4a 73 6f 6e } //Newtonsoft.Json  1
		$a_80_1 = {39 63 61 33 35 38 61 61 2d 33 31 37 62 2d 34 39 32 35 2d 38 61 64 61 2d 34 61 32 39 65 39 34 33 61 33 36 33 } //9ca358aa-317b-4925-8ada-4a29e943a363  1
		$a_80_2 = {4a 73 6f 6e 57 6f 72 6b 65 72 } //JsonWorker  1
		$a_80_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  1
		$a_80_4 = {47 65 74 54 79 70 65 73 } //GetTypes  1
		$a_80_5 = {47 65 74 4d 65 74 68 6f 64 73 } //GetMethods  1
		$a_80_6 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //InvokeMember  1
		$a_80_7 = {52 65 70 6c 61 63 65 } //Replace  1
		$a_80_8 = {47 5a 69 70 53 74 72 65 61 6d } //GZipStream  1
		$a_80_9 = {54 6f 41 72 72 61 79 } //ToArray  1
		$a_80_10 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //MemoryStream  1
		$a_80_11 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //CompressionMode  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1) >=12
 
}