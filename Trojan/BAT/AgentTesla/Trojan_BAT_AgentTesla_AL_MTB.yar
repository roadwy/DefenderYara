
rule Trojan_BAT_AgentTesla_AL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {26 00 11 05 7b 10 00 00 04 28 21 00 00 0a 28 22 00 00 0a 6f 23 00 00 0a 00 dd 05 } //2
		$a_01_1 = {52 00 46 00 45 00 53 00 58 00 47 00 2e 00 65 00 78 00 65 00 } //1 RFESXG.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_AL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {18 9a 20 21 03 00 00 95 e0 95 7e 60 00 00 04 18 9a 20 8e 04 00 00 95 61 08 0a 7e 60 00 00 04 18 9a 20 df 0d 00 00 95 2e 03 17 2b 01 16 58 } //2
		$a_01_1 = {18 9a 20 68 0c 00 00 95 2e 03 16 2b 01 17 17 59 7e 60 00 00 04 18 9a 20 40 0a 00 00 95 5f 7e 60 00 00 04 18 9a 20 91 0f 00 00 95 61 58 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_BAT_AgentTesla_AL_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 17 9a 28 50 90 01 02 0a 28 14 90 01 02 06 0c 02 07 19 9a 28 50 90 01 02 0a 28 14 90 01 02 06 0d 28 06 90 01 02 06 6f 4a 90 01 02 0a 06 72 39 90 01 02 70 07 18 9a 90 0a 53 00 6f 4b 90 01 02 0a 6f 4c 90 01 02 0a 0a 28 4d 90 01 02 0a 28 4e 90 01 02 0a 72 1f 90 01 02 70 15 16 28 4f 90 01 02 0a 0b 02 90 00 } //2
		$a_03_1 = {1a 9a 28 51 90 01 02 0a 09 16 6f 52 90 01 02 0a 00 06 72 39 90 01 02 70 07 18 9a 90 0a 36 00 28 51 90 01 02 0a 08 16 6f 52 90 01 02 0a 00 28 06 90 01 02 06 6f 4a 90 01 02 0a 06 72 39 90 01 02 70 07 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}