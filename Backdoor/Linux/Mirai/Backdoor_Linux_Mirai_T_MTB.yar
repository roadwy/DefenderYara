
rule Backdoor_Linux_Mirai_T_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.T!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 6b 69 6c 6c 61 6c 6c 62 6f 74 73 } //01 00  .killallbots
		$a_00_1 = {2e 6f 76 68 62 79 70 61 73 73 } //01 00  .ovhbypass
		$a_00_2 = {65 63 68 6f 20 27 40 72 65 62 6f 6f 74 } //01 00  echo '@reboot
		$a_00_3 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //00 00  npxXoudifFeEgGaACScs
	condition:
		any of ($a_*)
 
}