
rule Trojan_BAT_AgentTesla_AFK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 07 91 13 08 11 06 17 58 08 5d 13 09 07 11 06 91 11 08 61 07 11 09 91 59 20 00 01 00 00 58 13 0a 07 11 06 11 0a 20 ff 00 00 00 5f d2 9c 11 06 17 58 13 06 11 06 07 8e 69 32 aa } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AgentTesla_AFK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 72 79 70 74 6f 4f 62 66 75 73 63 61 74 6f 72 5f 4f 75 74 70 75 74 5c 48 48 48 38 38 37 2e 70 64 62 } //2 CryptoObfuscator_Output\HHH887.pdb
		$a_01_1 = {48 48 48 38 38 37 2e 50 72 6f 70 65 72 74 69 65 73 } //2 HHH887.Properties
		$a_01_2 = {24 34 32 38 39 62 31 39 35 2d 61 63 36 36 2d 34 31 63 38 2d 62 36 38 30 2d 36 38 37 64 30 32 34 62 66 33 31 37 } //2 $4289b195-ac66-41c8-b680-687d024bf317
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}