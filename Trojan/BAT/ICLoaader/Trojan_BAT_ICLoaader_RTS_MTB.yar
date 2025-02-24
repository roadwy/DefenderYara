
rule Trojan_BAT_ICLoaader_RTS_MTB{
	meta:
		description = "Trojan:BAT/ICLoaader.RTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 4d 53 49 52 65 61 70 65 72 } //1 AMSIReaper
		$a_01_1 = {50 52 4f 43 45 53 53 5f 56 4d 5f 4f 50 45 52 41 54 49 4f 4e } //1 PROCESS_VM_OPERATION
		$a_01_2 = {76 34 2e 30 2e 33 30 33 31 39 } //1 v4.0.30319
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}