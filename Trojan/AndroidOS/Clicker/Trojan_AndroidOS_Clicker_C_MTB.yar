
rule Trojan_AndroidOS_Clicker_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Clicker.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 69 61 70 70 2f 64 6f 77 6e 6c 6f 61 64 66 69 6c 65 64 69 72 2f 74 65 6d 70 64 65 66 61 75 6c 74 64 6f 77 6e 66 69 6c 65 } //1 /iapp/downloadfiledir/tempdefaultdownfile
		$a_00_1 = {63 6c 69 63 6b 69 } //1 clicki
		$a_00_2 = {6c 63 6f 6d 2f 69 61 70 70 2f 61 70 70 2f 6c 6f 67 6f 61 63 74 69 76 69 74 79 } //1 lcom/iapp/app/logoactivity
		$a_00_3 = {74 6f 75 63 68 6d 6f 6e 69 74 6f 72 } //1 touchmonitor
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}