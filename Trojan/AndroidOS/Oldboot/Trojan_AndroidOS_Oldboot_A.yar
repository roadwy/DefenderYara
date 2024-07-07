
rule Trojan_AndroidOS_Oldboot_A{
	meta:
		description = "Trojan:AndroidOS/Oldboot.A,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 7a 79 36 2e 63 6f 6d 2c 6c 61 6e 64 66 79 2e 63 6f 6d 2c 33 36 36 6a 6f 62 73 2e 63 6f 6d 00 } //1
		$a_01_1 = {61 6e 64 72 6f 6c 64 39 39 39 2e 63 6f 6d 3a 38 30 39 30 2f 62 61 63 6b 75 72 6c 2e 64 6f 00 } //1
		$a_01_2 = {61 6e 64 72 6f 69 64 2e 67 6f 6f 67 6c 65 6b 65 72 6e 65 6c 2f 2f 64 62 2f 2f 69 74 2e 69 00 } //1
		$a_01_3 = {3a 38 30 39 30 2f 69 6e 73 74 61 6c 6c 61 70 70 2e 64 6f 00 } //1 㠺㤰⼰湩瑳污慬灰搮o
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_AndroidOS_Oldboot_A_2{
	meta:
		description = "Trojan:AndroidOS/Oldboot.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3f 63 61 72 64 69 64 3d 00 } //1
		$a_01_1 = {26 61 70 70 69 64 3d 00 0b 26 63 68 61 6e 6e 65 6c 69 64 3d 00 05 26 6e 65 74 3d 00 } //1 愦灰摩=☋档湡敮楬㵤Ԁ渦瑥=
		$a_01_2 = {31 30 2e 30 2e 30 2e 31 37 32 00 0a 31 30 2e 30 2e 30 2e 32 30 30 00 } //1
		$a_01_3 = {73 65 72 76 69 63 65 2f 42 6f 6f 74 52 65 63 76 3b 00 } //1 敳癲捩⽥潂瑯敒癣;
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}