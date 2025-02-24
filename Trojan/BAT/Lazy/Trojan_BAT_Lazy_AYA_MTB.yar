
rule Trojan_BAT_Lazy_AYA_MTB{
	meta:
		description = "Trojan:BAT/Lazy.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {07 11 05 07 11 05 91 11 04 11 05 11 04 8e b7 5d 91 61 9c 00 11 05 17 d6 13 05 11 05 11 07 13 08 11 08 31 dc } //2
		$a_01_1 = {73 6e 61 6b 65 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //2 snake.My.Resources
		$a_01_2 = {44 65 63 72 79 70 74 50 61 79 6c 6f 61 64 } //1 DecryptPayload
		$a_01_3 = {45 78 65 63 75 74 65 50 61 79 6c 6f 61 64 } //1 ExecutePayload
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}