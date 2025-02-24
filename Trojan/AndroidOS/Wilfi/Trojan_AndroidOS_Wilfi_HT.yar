
rule Trojan_AndroidOS_Wilfi_HT{
	meta:
		description = "Trojan:AndroidOS/Wilfi.HT,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 39 35 2e 31 30 2e 32 30 35 2e 32 32 33 3a 35 30 30 30 2f 76 61 6e 69 6c 6c 61 } //1 195.10.205.223:5000/vanilla
		$a_01_1 = {45 72 72 6f 72 20 77 68 69 6c 65 20 73 65 6e 64 69 6e 67 20 53 4d 53 20 64 61 74 61 } //1 Error while sending SMS data
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}