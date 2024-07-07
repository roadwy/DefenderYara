
rule Trojan_BAT_AgentTesla_MAG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {26 09 06 6f 90 01 03 0a 08 07 6f 90 01 03 0a 11 0f 17 58 13 0f 02 28 90 01 03 06 11 06 11 0c 5d 90 00 } //5
		$a_01_1 = {57 37 a2 0b 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 a4 00 00 00 32 00 00 00 8e } //5
		$a_01_2 = {32 63 61 36 34 63 62 35 2d 39 35 65 34 2d 34 36 34 30 2d 61 31 61 66 2d 34 37 38 65 66 65 35 62 37 31 64 61 } //1 2ca64cb5-95e4-4640-a1af-478efe5b71da
		$a_01_3 = {47 65 63 69 6b 6d 65 48 65 73 61 70 6c 61 2e 50 72 6f 70 65 72 74 69 65 73 } //1 GecikmeHesapla.Properties
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}