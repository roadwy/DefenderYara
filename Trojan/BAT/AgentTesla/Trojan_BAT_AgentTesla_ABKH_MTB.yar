
rule Trojan_BAT_AgentTesla_ABKH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 00 6c 00 6c 00 69 00 63 00 6f 00 74 00 74 00 76 00 69 00 6c 00 6c 00 65 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 43 00 53 00 33 } //2
		$a_01_1 = {41 00 72 00 65 00 5f 00 41 00 69 00 72 00 50 00 6f 00 64 00 73 00 5f 00 57 00 61 00 74 00 65 00 72 00 70 00 72 00 6f 00 6f 00 66 00 5f 00 74 00 68 00 65 00 5f 00 73 00 69 00 6d 00 70 00 6c 00 65 00 5f 00 61 00 6e 00 73 00 77 00 65 00 72 00 5f 00 69 00 73 00 5f 00 4e 00 6f 00 } //2 Are_AirPods_Waterproof_the_simple_answer_is_No
		$a_01_2 = {52 00 65 00 61 00 73 00 6f 00 6e 00 73 00 5f 00 74 00 6f 00 5f 00 41 00 6c 00 6c 00 6f 00 77 00 5f 00 50 00 6f 00 70 00 5f 00 55 00 70 00 73 00 5f 00 53 00 61 00 66 00 61 00 72 00 69 00 } //2 Reasons_to_Allow_Pop_Ups_Safari
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}