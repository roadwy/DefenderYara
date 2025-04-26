
rule Trojan_AndroidOS_Ligshar_A{
	meta:
		description = "Trojan:AndroidOS/Ligshar.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 66 69 67 46 61 69 6c 44 61 79 73 31 } //2 ConfigFailDays1
		$a_01_1 = {52 65 63 6f 72 64 46 61 69 6c 54 69 6d 65 73 31 } //2 RecordFailTimes1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}