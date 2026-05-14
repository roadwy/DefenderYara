
rule Trojan_BAT_Cassandra_SM_MTB{
	meta:
		description = "Trojan:BAT/Cassandra.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {43 61 73 68 61 72 6b 5a 6f 6f 74 2e 64 6c 6c } //1 CasharkZoot.dll
		$a_81_1 = {43 61 73 68 54 6f 45 61 72 6e 20 69 73 20 61 20 72 65 77 61 72 64 73 20 70 6c 61 74 66 6f 72 6d 20 77 68 65 72 65 20 79 6f 75 20 65 61 72 6e 20 63 61 73 68 20 6f 72 20 63 72 79 70 74 6f 20 62 79 20 63 6f 6d 70 6c 65 74 69 6e 67 20 74 61 73 6b 73 20 6c 69 6b 65 20 73 75 72 76 65 79 73 } //1 CashToEarn is a rewards platform where you earn cash or crypto by completing tasks like surveys
		$a_81_2 = {32 2e 33 2e 39 2e 38 } //1 2.3.9.8
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}