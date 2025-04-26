
rule Trojan_BAT_AgentTesla_DNB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 02 11 04 91 07 61 06 74 ?? ?? ?? 1b 09 91 61 d2 9c } //1
		$a_01_1 = {24 39 66 62 38 32 30 36 65 2d 34 30 30 66 2d 34 33 36 30 2d 39 35 37 39 2d 30 39 36 31 31 61 37 62 66 61 36 35 } //1 $9fb8206e-400f-4360-9579-09611a7bfa65
		$a_01_2 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_01_3 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}