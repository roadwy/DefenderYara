
rule Trojan_MacOS_ApFellDownload_A{
	meta:
		description = "Trojan:MacOS/ApFellDownload.A,SIGNATURE_TYPE_MACHOHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 90 02 20 3a 38 30 90 02 25 2e 6a 73 90 02 10 66 61 69 6c 65 64 20 74 6f 20 66 65 74 63 68 20 64 61 74 61 20 66 72 6f 6d 20 74 68 65 20 75 72 6c 90 00 } //2
		$a_00_1 = {48 bf 4a 61 76 61 53 63 72 69 48 be 70 74 00 00 00 00 00 ea e8 60 2b 00 00 } //3
		$a_00_2 = {40 29 8c d2 c0 2e ac f2 60 6a cc f2 40 2e ed f2 01 8e 8e d2 01 40 fd f2 70 06 00 94 } //3
		$a_00_3 = {5f 4f 42 4a 43 5f 43 4c 41 53 53 5f 24 5f 4f 53 41 53 63 72 69 70 74 } //2 _OBJC_CLASS_$_OSAScript
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*3+(#a_00_2  & 1)*3+(#a_00_3  & 1)*2) >=7
 
}