
rule Trojan_BAT_Loki_MBWD_MTB{
	meta:
		description = "Trojan:BAT/Loki.MBWD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 4b 67 69 66 78 39 48 5a 35 67 54 5a 4b 4d 6a 73 } //2 QKgifx9HZ5gTZKMjs
		$a_01_1 = {57 32 45 79 71 6b 5a 67 00 38 5a 6d 4d 6e 6a 59 47 55 54 4b 76 79 } //1 ㉗祅歱杚㠀浚湍奪啇䭔祶
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}