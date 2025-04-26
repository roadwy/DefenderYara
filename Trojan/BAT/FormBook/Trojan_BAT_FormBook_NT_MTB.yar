
rule Trojan_BAT_FormBook_NT_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 00 00 5f d2 61 d2 81 } //5
		$a_81_1 = {63 61 30 36 39 31 37 32 2d 62 31 34 61 2d 34 30 63 34 2d 62 31 33 37 2d 61 63 35 37 32 31 64 61 64 31 38 63 } //5 ca069172-b14a-40c4-b137-ac5721dad18c
		$a_81_2 = {43 3a 5c 74 65 6d 70 5c 4e 5a 45 53 4c 2e 6d 64 62 } //1 C:\temp\NZESL.mdb
	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*1) >=11
 
}