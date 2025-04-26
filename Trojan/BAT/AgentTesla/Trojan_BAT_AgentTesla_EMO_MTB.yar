
rule Trojan_BAT_AgentTesla_EMO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {78 6b a9 31 36 39 31 64 75 31 64 35 8e 9b 31 71 cf 64 31 35 71 77 39 35 71 39 31 35 39 31 64 71 31 64 35 71 64 31 71 77 64 31 35 71 77 39 35 31 39 31 35 39 31 64 71 31 } //1
		$a_01_1 = {10 8d 38 7d a9 50 65 0c 5c 02 44 41 03 18 03 43 54 1c 57 5a 54 5f 57 5e 41 19 53 01 51 43 11 5b 51 0d 5f 51 33 2b 62 15 1c 18 5d 50 1f 34 3c 3f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}