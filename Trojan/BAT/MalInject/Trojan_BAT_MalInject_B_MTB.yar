
rule Trojan_BAT_MalInject_B_MTB{
	meta:
		description = "Trojan:BAT/MalInject.B!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 61 6c 68 65 75 72 65 75 78 00 43 6f 70 79 41 72 72 61 79 00 47 65 74 45 6e 74 72 79 41 73 73 65 6d 62 6c 79 00 42 6c 6f 63 6b 43 6f 70 79 } //1
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 00 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 } //1 湉潶敫敍扭牥匀数楣污潆摬牥
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}