
rule Trojan_AndroidOS_Congur_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Congur.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 32 39 66 65 35 36 66 61 35 39 61 62 30 64 62 } //1 c29fe56fa59ab0db
		$a_00_1 = {4c 63 6f 6d 2f 78 63 67 64 6d 6d 73 6a 2f 42 41 48 } //1 Lcom/xcgdmmsj/BAH
		$a_00_2 = {63 6f 6d 2e 78 63 67 64 6d 6d 73 6a 2e 4d 79 41 64 6d 69 6e } //1 com.xcgdmmsj.MyAdmin
		$a_00_3 = {6c 6f 63 6b 4e 6f 77 } //1 lockNow
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}