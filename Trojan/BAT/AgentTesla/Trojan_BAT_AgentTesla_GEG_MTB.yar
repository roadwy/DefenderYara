
rule Trojan_BAT_AgentTesla_GEG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {50 6f 72 61 6c 50 65 72 69 6c 5f 53 74 65 66 61 6e 54 69 63 75 } //PoralPeril_StefanTicu  01 00 
		$a_01_1 = {49 6e 76 6f 6b 65 } //03 00  Invoke
		$a_01_2 = {68 47 64 38 52 34 52 54 62 73 72 34 53 35 50 79 6e 53 } //03 00  hGd8R4RTbsr4S5PynS
		$a_01_3 = {48 6f 51 4d 50 47 4a 4d 38 63 6f 70 39 66 65 59 54 36 } //00 00  HoQMPGJM8cop9feYT6
	condition:
		any of ($a_*)
 
}