
rule Trojan_BAT_AgentTesla_CQJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CQJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {39 66 62 38 32 30 36 65 2d 34 30 30 66 2d 34 33 36 30 2d 39 35 37 39 2d 30 39 36 31 31 61 37 62 66 61 36 35 } //1 9fb8206e-400f-4360-9579-09611a7bfa65
		$a_01_1 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_01_2 = {42 69 74 6d 61 70 } //1 Bitmap
		$a_01_3 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_6 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}