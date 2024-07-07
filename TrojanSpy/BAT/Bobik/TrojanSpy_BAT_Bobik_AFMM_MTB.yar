
rule TrojanSpy_BAT_Bobik_AFMM_MTB{
	meta:
		description = "TrojanSpy:BAT/Bobik.AFMM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b 0a 06 09 16 11 04 6f 24 00 00 0a 08 09 16 09 8e 69 6f 31 00 00 0a 25 13 04 16 30 e5 } //2
		$a_01_1 = {49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 } //1 Install.Resource
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}