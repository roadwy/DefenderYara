
rule Trojan_BAT_Smokeloader_AMBA_MTB{
	meta:
		description = "Trojan:BAT/Smokeloader.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 09 07 09 91 06 59 d2 9c 09 17 58 0d 09 07 8e 69 32 ed } //5
		$a_01_1 = {54 d5 29 5c 70 71 7b 28 78 7a 77 6f 7a 69 75 28 6b 69 76 76 77 7c 28 6a 6d 28 7a 7d 76 28 71 76 28 4c 57 5b 28 75 77 6c 6d 36 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}