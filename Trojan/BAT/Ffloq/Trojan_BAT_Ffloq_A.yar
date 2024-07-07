
rule Trojan_BAT_Ffloq_A{
	meta:
		description = "Trojan:BAT/Ffloq.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 65 74 5f 45 78 70 65 63 74 31 30 30 43 6f 6e 74 69 6e 75 65 } //1 set_Expect100Continue
		$a_01_1 = {46 69 72 65 66 6f 78 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Firefox.Resources.resources
		$a_01_2 = {43 6f 6e 66 75 73 65 72 45 78 20 76 30 2e } //1 ConfuserEx v0.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}