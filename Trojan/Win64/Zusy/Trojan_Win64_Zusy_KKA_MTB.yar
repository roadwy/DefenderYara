
rule Trojan_Win64_Zusy_KKA_MTB{
	meta:
		description = "Trojan:Win64/Zusy.KKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {c0 e2 04 44 00 da 88 14 06 48 ff c0 83 c1 03 49 39 c0 } //20
		$a_01_1 = {70 61 79 6c 6f 61 64 5f 74 65 6d 70 2e 64 6c 6c } //10 payload_temp.dll
		$a_01_2 = {5f 70 61 79 6c 6f 61 64 5f 69 6e 69 74 } //5 _payload_init
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}