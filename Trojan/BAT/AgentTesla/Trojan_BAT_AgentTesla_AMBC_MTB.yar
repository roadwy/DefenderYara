
rule Trojan_BAT_AgentTesla_AMBC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 61 07 11 90 01 01 20 90 01 04 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AgentTesla_AMBC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AMBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {36 00 36 00 37 00 39 00 36 00 34 00 37 00 39 00 36 00 33 00 37 00 46 00 36 00 5a 00 37 00 43 00 5a 00 33 00 37 00 35 00 36 00 41 00 37 00 39 00 36 00 33 00 35 00 5a 00 37 00 35 00 37 00 46 00 36 00 32 00 37 00 37 00 34 00 34 00 37 00 45 00 36 00 35 00 36 00 33 00 36 00 32 00 37 00 35 00 36 00 5a 00 37 00 31 00 31 00 33 00 37 00 35 00 36 00 41 00 37 } //1
		$a_80_1 = {58 75 5f 4c 79 5f 44 61 5f 54 68 75 63 2e 46 6f 72 6d 4d 61 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //Xu_Ly_Da_Thuc.FormMain.resources  1
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}