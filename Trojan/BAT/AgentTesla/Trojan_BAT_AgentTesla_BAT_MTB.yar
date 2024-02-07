
rule Trojan_BAT_AgentTesla_BAT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {31 00 38 00 35 00 2e 00 32 00 34 00 36 00 2e 00 32 00 32 00 30 00 2e 00 31 00 32 00 31 00 2f 00 76 00 69 00 6b 00 2f 00 64 00 6c 00 6c 00 6c 00 2e 00 74 00 78 00 74 00 } //01 00  185.246.220.121/vik/dlll.txt
		$a_01_1 = {53 30 6a 7e 74 23 6e 35 46 23 66 52 64 50 55 35 4d 6b 70 } //01 00  S0j~t#n5F#fRdPU5Mkp
		$a_01_2 = {48 00 41 00 57 00 4b 00 2e 00 48 00 41 00 57 00 4b 00 } //01 00  HAWK.HAWK
		$a_01_3 = {76 00 69 00 6b 00 2f 00 62 00 72 00 75 00 6e 00 6f 00 2e 00 74 00 78 00 74 00 } //00 00  vik/bruno.txt
	condition:
		any of ($a_*)
 
}