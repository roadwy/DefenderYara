
rule TrojanSpy_AndroidOS_Asacub_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Asacub.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 c6 d0 80 fe 0a 83 d7 00 8a 74 08 02 41 84 f6 [0-05] 89 46 10 89 e3 83 c7 0f 83 e7 f0 29 fb 89 5e 04 89 dc 85 c9 [0-05] 31 ff 31 db [0-05] 90 90 8b 46 10 0f b6 54 38 01 47 88 d6 80 c6 d0 80 fe 09 [0-05] 89 d0 89 da 8b 5e 04 88 04 13 89 d3 43 39 cf } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}