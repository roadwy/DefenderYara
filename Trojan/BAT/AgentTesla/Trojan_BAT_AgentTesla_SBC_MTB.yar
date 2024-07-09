
rule Trojan_BAT_AgentTesla_SBC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {08 07 09 20 00 c4 00 00 28 ?? ?? ?? 06 0b 00 09 15 58 0d 09 16 fe 04 16 fe 01 13 04 11 04 2d df } //1
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_2 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_01_3 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_4 = {4c 00 61 00 73 00 74 00 46 00 6d 00 53 00 6e 00 61 00 72 00 6c 00 73 00 } //1 LastFmSnarls
		$a_01_5 = {47 00 48 00 34 00 35 00 47 00 4a 00 31 00 34 00 47 00 34 00 45 00 35 00 47 00 59 00 51 00 44 00 34 00 53 00 47 00 4f 00 38 00 37 00 } //1 GH45GJ14G4E5GYQD4SGO87
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}