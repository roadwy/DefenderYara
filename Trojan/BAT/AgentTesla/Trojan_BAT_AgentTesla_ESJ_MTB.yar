
rule Trojan_BAT_AgentTesla_ESJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ESJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {58 d5 3e 87 f9 e5 7f 44 6a c9 06 04 07 03 c4 32 75 94 2a 0e a3 09 7d 77 19 dc 87 9a b1 c1 79 70 49 87 3b e3 97 c1 dd ed f0 c0 bc ad 98 f7 6e 1f } //1
		$a_01_1 = {15 1c ee 39 8e ca d8 61 bc e5 9f 1d 3a 29 00 95 ca 6a e4 17 7b f0 d2 69 b4 fa 29 2c ce b7 a1 6f 4b 95 d7 e7 3d 46 1c 86 dc b6 68 3b 5a 67 db d2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}