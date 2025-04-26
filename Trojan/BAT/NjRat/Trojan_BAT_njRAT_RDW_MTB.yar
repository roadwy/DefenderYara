
rule Trojan_BAT_njRAT_RDW_MTB{
	meta:
		description = "Trojan:BAT/njRAT.RDW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 6e 63 72 79 70 74 69 6f 6e 20 53 65 72 76 65 72 } //1 Encryption Server
		$a_01_1 = {6d 4b 46 47 49 4f 5a 57 5a 58 4c 45 41 43 5a 50 4e 43 45 42 50 46 } //1 mKFGIOZWZXLEACZPNCEBPF
		$a_01_2 = {6d 4e 45 41 50 44 54 44 49 4a 47 54 42 4a 46 41 52 } //1 mNEAPDTDIJGTBJFAR
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}