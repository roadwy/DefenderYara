
rule Trojan_BAT_AgentTesla_MBGX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 2e 00 67 00 67 00 2f 00 66 00 6e 00 64 00 65 00 76 00 } //1 https://discord.gg/fndev
		$a_01_1 = {31 66 66 30 62 37 30 39 2d 32 61 61 37 2d 34 31 62 31 2d 39 61 32 32 2d 34 64 31 34 34 36 31 66 64 64 32 30 } //1 1ff0b709-2aa7-41b1-9a22-4d14461fdd20
		$a_01_2 = {41 00 74 00 6f 00 6d 00 69 00 63 00 5f 00 4c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 } //1 Atomic_Launcher.Properties.Resource
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}