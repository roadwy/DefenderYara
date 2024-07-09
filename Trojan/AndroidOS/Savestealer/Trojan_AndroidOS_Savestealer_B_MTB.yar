
rule Trojan_AndroidOS_Savestealer_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Savestealer.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {65 74 65 72 6e 69 74 79 70 72 2e [0-03] 2f 61 70 69 2f 61 63 63 6f 75 6e 74 73 } //1
		$a_01_1 = {4c 63 6f 6d 2f 65 74 65 72 6e 69 74 79 2f } //1 Lcom/eternity/
		$a_01_2 = {73 61 76 65 64 61 74 00 } //1 慳敶慤t
		$a_01_3 = {77 65 62 68 6f 6f 6b 75 72 6c 00 } //1
		$a_01_4 = {2f 63 6f 6d 2e 72 74 73 6f 66 74 2e 67 72 6f 77 74 6f 70 69 61 2f 66 69 6c 65 73 2f 73 61 76 65 2e 64 61 74 } //1 /com.rtsoft.growtopia/files/save.dat
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}