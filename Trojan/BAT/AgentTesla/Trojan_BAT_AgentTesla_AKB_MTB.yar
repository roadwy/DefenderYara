
rule Trojan_BAT_AgentTesla_AKB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 16 73 90 01 03 0a 0c 73 90 01 03 0a 0d 08 09 28 90 01 03 06 09 16 6a 6f 90 01 03 0a 09 13 04 dd 90 01 04 08 39 90 01 04 08 6f 90 01 03 0a dc 07 39 90 01 04 07 6f 90 01 03 0a dc 06 02 90 00 } //10
		$a_80_1 = {63 6f 73 74 75 72 61 2e 63 6c 61 73 73 6c 69 62 72 61 72 79 31 2e 64 6c 6c } //costura.classlibrary1.dll  2
		$a_80_2 = {52 65 61 64 45 78 69 73 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //ReadExistingAssembly  2
		$a_80_3 = {52 65 61 64 46 72 6f 6d 45 6d 62 65 64 64 65 64 52 65 73 6f 75 72 63 65 73 } //ReadFromEmbeddedResources  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=16
 
}