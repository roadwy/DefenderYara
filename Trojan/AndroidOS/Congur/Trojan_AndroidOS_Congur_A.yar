
rule Trojan_AndroidOS_Congur_A{
	meta:
		description = "Trojan:AndroidOS/Congur.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 69 72 75 73 53 65 72 76 69 63 65 24 31 30 30 30 30 30 30 30 30 } //2 VirusService$100000000
		$a_01_1 = {76 65 69 6c 5f 6c 69 66 74 65 64 } //1 veil_lifted
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}