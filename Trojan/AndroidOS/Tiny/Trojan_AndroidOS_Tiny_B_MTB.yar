
rule Trojan_AndroidOS_Tiny_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Tiny.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 6c 69 62 32 2f 41 64 41 63 74 69 76 69 74 79 } //1 Lcom/lib2/AdActivity
		$a_01_1 = {63 6f 6d 2f 6c 69 62 32 2f 4d 52 65 63 65 69 76 65 72 } //1 com/lib2/MReceiver
		$a_01_2 = {63 6f 6d 2f 6c 69 62 32 2f 50 61 67 65 6c 6f 61 64 41 63 74 69 76 69 74 79 } //1 com/lib2/PageloadActivity
		$a_01_3 = {2f 6c 69 62 32 2f 41 64 53 6d 61 6c 6c 41 63 74 69 76 69 74 79 } //1 /lib2/AdSmallActivity
		$a_01_4 = {2f 6c 69 62 32 2f 53 65 72 76 69 63 65 } //1 /lib2/Service
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}