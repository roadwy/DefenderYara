
rule Trojan_BAT_AgentTesla_SC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 16 5d 91 61 07 11 04 17 58 09 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 13 08 07 11 07 11 08 9c 11 05 07 11 07 91 6f 59 00 00 0a 11 04 17 58 13 04 11 04 09 08 17 58 5a 32 a8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AgentTesla_SC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 17 58 13 0e 11 06 20 00 56 01 00 5d 13 0b 11 09 11 0b 91 13 0f 11 06 1f 16 5d 13 10 11 09 11 0b 11 0f 1f 16 8d 06 00 00 01 25 d0 15 00 00 04 28 ?? ?? ?? 0a 11 10 91 61 11 09 11 0e 20 00 56 01 00 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 11 06 17 58 13 06 11 06 20 00 56 01 00 fe 04 13 11 11 11 2d 97 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AgentTesla_SC_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {20 ec 8e fb 0e 0b 07 20 fb 8e fb 0e fe 01 13 09 11 09 2c 09 20 1c 8f fb 0e 0b 00 2b 1f 07 20 ce 8e fb 0e } //10
		$a_00_1 = {2f 00 63 00 20 00 6e 00 65 00 74 00 20 00 73 00 74 00 61 00 72 00 74 00 } //3 /c net start
		$a_80_2 = {47 65 74 46 69 6c 65 4e 61 6d 65 42 79 55 52 4c } //GetFileNameByURL  3
		$a_80_3 = {52 6f 74 31 33 } //Rot13  3
		$a_80_4 = {37 6f 30 55 4c 4f 6b 57 79 76 48 7a 59 32 33 58 72 33 39 58 39 48 65 4b 34 55 46 75 50 56 4f 74 52 6c 47 4c 78 52 4e 44 37 5a 54 56 6d 72 6e 46 37 4f 31 63 45 6c 5a 63 64 6c 64 4f 6c 7a 49 4a 4d 49 31 7a 53 78 51 5a 37 4d 32 38 39 39 35 37 37 37 33 33 33 61 69 69 69 73 72 36 42 35 31 42 57 } //7o0ULOkWyvHzY23Xr39X9HeK4UFuPVOtRlGLxRND7ZTVmrnF7O1cElZcdldOlzIJMI1zSxQZ7M28995777333aiiisr6B51BW  3
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}