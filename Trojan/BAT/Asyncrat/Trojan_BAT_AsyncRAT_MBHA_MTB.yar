
rule Trojan_BAT_AsyncRAT_MBHA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MBHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 00 71 00 51 00 23 00 23 00 4d 00 23 00 23 00 23 00 23 00 45 00 23 00 23 00 23 00 23 00 2f 00 2f 00 38 00 23 00 23 00 4c 00 67 00 23 00 23 00 23 00 23 00 23 00 23 00 23 00 23 00 23 00 51 00 23 00 23 00 23 00 23 00 23 00 } //1 VqQ##M####E####//8##Lg#########Q#####
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}