
rule Trojan_BAT_Stealer_SGA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SGA!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 6f 64 75 6c 65 2e 74 65 6c 65 67 } //1 module.teleg
		$a_01_1 = {45 00 78 00 6f 00 64 00 75 00 73 00 2e 00 77 00 61 00 6c 00 6c 00 65 00 74 00 } //1 Exodus.wallet
		$a_01_2 = {76 00 68 00 34 00 32 00 38 00 2e 00 74 00 69 00 6d 00 65 00 77 00 65 00 62 00 2e 00 72 00 75 00 2f 00 } //1 vh428.timeweb.ru/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}