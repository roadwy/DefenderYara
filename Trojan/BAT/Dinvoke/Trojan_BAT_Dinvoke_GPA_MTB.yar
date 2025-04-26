
rule Trojan_BAT_Dinvoke_GPA_MTB{
	meta:
		description = "Trojan:BAT/Dinvoke.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 00 71 00 51 00 c7 05 44 00 4d 00 41 00 c7 05 44 00 41 00 45 00 c7 05 44 00 41 00 41 00 } //5
		$a_01_1 = {e2 05 52 00 34 00 67 00 e7 05 52 00 34 00 67 00 d4 05 40 00 39 00 54 00 cf 05 42 00 31 00 76 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}