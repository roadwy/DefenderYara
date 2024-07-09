
rule Trojan_BAT_AgentTesla_NGE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 10 8d 5b 00 00 01 13 14 11 09 28 ?? ?? 00 0a 16 11 14 16 1a 28 ?? ?? 00 0a 11 0a 28 ?? ?? 00 0a 16 11 14 1a 1a 28 ?? ?? 00 0a 11 0b 28 ?? ?? 00 0a 16 11 14 1e 1a 28 ?? ?? 00 0a } //5
		$a_01_1 = {50 00 65 00 72 00 66 00 65 00 63 00 74 00 53 00 63 00 72 00 69 00 70 00 74 00 20 00 31 00 39 00 } //1 PerfectScript 19
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_NGE_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 95 00 00 0a 26 73 ?? 00 00 0a 26 08 28 ?? 00 00 0a 02 6f ?? 00 00 0a 6f ?? 00 00 0a 73 ?? 00 00 0a 26 73 ?? 00 00 0a 26 08 06 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 26 73 ?? 00 00 0a 26 73 ?? 00 00 0a 26 73 ?? 00 00 0a 26 07 73 ?? 00 00 0a } //5
		$a_01_1 = {57 77 30 78 34 5f 31 70 71 32 41 54 54 6a 72 } //1 Ww0x4_1pq2ATTjr
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_NGE_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {03 8e 69 8d ?? ?? ?? 01 13 04 09 11 04 16 03 8e 69 6f ?? ?? ?? 0a 13 05 11 04 11 05 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 13 06 de 2c } //1
		$a_01_1 = {42 00 30 04 20 00 6c 00 6f 00 42 04 20 00 32 04 30 04 48 04 63 00 33 04 30 04 20 00 31 04 40 04 3e 04 32 04 6b 00 20 00 32 04 4b 04 20 00 53 00 43 04 34 04 } //1 Bа loт вашcга бровk вы Sуд
		$a_01_2 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_3 = {4b 00 30 04 36 04 3d 04 65 00 20 00 30 04 34 04 37 04 3d 04 30 04 79 00 4b 04 46 04 4c 04 } //1 Kажнe адзнаyыць
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}