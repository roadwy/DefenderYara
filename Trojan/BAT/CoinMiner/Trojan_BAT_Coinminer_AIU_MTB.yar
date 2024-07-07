
rule Trojan_BAT_Coinminer_AIU_MTB{
	meta:
		description = "Trojan:BAT/Coinminer.AIU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 00 78 00 65 00 2e 00 72 00 65 00 70 00 6c 00 65 00 68 00 5c 00 61 00 74 00 61 00 44 00 6d 00 61 00 72 00 67 00 6f 00 72 00 50 00 5c 00 3a 00 43 00 } //1 exe.repleh\ataDmargorP\:C
		$a_01_1 = {2f 00 31 00 35 00 2e 00 31 00 36 00 31 00 2e 00 37 00 30 00 31 00 2e 00 39 00 30 00 31 00 2f 00 2f 00 3a 00 70 00 74 00 74 00 68 00 } //1 /15.161.701.901//:ptth
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}