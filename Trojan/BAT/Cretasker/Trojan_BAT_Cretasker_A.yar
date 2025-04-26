
rule Trojan_BAT_Cretasker_A{
	meta:
		description = "Trojan:BAT/Cretasker.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 00 6d 00 78 00 76 00 64 00 30 00 78 00 68 00 65 00 57 00 39 00 31 00 64 00 46 00 42 00 68 00 62 00 6d 00 56 00 73 00 4d 00 54 00 59 00 3d 00 } //1 Rmxvd0xheW91dFBhbmVsMTY=
		$a_01_1 = {43 6f 6e 66 75 73 65 72 45 78 20 76 31 2e 30 2e 30 } //1 ConfuserEx v1.0.0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}