
rule Trojan_BAT_AgentTesla_NRL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NRL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 11 07 11 09 6f ?? ?? ?? 0a 13 0a 11 0a 16 16 16 16 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 0b 11 0b 2c 2c 00 08 12 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 12 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 12 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 00 00 11 09 } //1
		$a_01_1 = {24 32 39 38 45 46 31 33 35 2d 37 31 44 44 2d 34 30 35 36 2d 41 33 46 30 2d 37 38 31 31 31 35 36 44 34 44 44 33 } //1 $298EF135-71DD-4056-A3F0-7811156D4DD3
		$a_01_2 = {4f 72 61 6c 20 50 61 74 68 6f 6c 6f 67 69 73 74 } //1 Oral Pathologist
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}