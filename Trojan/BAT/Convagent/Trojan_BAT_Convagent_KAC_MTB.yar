
rule Trojan_BAT_Convagent_KAC_MTB{
	meta:
		description = "Trojan:BAT/Convagent.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {59 00 75 00 78 00 7a 00 4f 00 57 00 78 00 68 00 54 00 37 00 65 00 35 00 52 00 76 00 53 00 49 00 30 00 63 00 6c 00 76 00 42 00 4d 00 79 00 33 00 4b 00 50 00 69 00 } //3 YuxzOWxhT7e5RvSI0clvBMy3KPi
		$a_01_1 = {56 00 6f 00 64 00 53 00 6d 00 6f 00 45 00 70 00 70 00 74 00 4e 00 31 00 7a 00 4f 00 63 00 69 } //3
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3) >=6
 
}