
rule Trojan_Win64_Rozena_SPQ_MTB{
	meta:
		description = "Trojan:Win64/Rozena.SPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 31 30 2e 32 31 31 2e 35 35 2e 32 3a 38 30 38 31 2f 6a 71 75 65 72 79 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2f 33 2e 36 2e 34 } //1 http://10.211.55.2:8081/jquery.com/download/3.6.4
	condition:
		((#a_01_0  & 1)*1) >=1
 
}