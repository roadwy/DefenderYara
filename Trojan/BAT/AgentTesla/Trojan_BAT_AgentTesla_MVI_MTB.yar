
rule Trojan_BAT_AgentTesla_MVI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 11 05 91 72 27 00 00 70 7e 1d 00 00 04 25 2d 17 26 7e 1c 00 00 04 fe 06 46 00 00 06 73 32 00 00 0a 25 80 1d 00 00 04 28 01 00 00 2b 28 02 00 00 2b 09 1f } //1
		$a_00_1 = {53 74 65 70 4e 61 76 69 67 61 74 69 6f 6e 20 57 69 7a 61 72 64 } //1 StepNavigation Wizard
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}