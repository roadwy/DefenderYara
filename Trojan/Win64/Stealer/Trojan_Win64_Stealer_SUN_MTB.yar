
rule Trojan_Win64_Stealer_SUN_MTB{
	meta:
		description = "Trojan:Win64/Stealer.SUN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {e8 f5 69 0c 00 48 83 7b 18 08 48 89 7b 10 72 05 48 8b 0b eb 03 48 8b cb 33 c0 66 89 04 79 48 8b 7c 24 30 48 8b 74 24 40 48 8b c3 48 8b 5c 24 38 } //1
		$a_81_1 = {2f 73 76 63 73 74 65 61 6c 65 72 2f 67 65 74 2e 70 68 70 } //1 /svcstealer/get.php
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}