
rule Trojan_MacOS_SAgnt_B_MTB{
	meta:
		description = "Trojan:MacOS/SAgnt.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_02_0 = {2f 67 65 61 63 6f 6e 5f [0-10] 2f 6d 61 69 6e 2e 67 6f } //5
		$a_00_1 = {63 73 5f 67 65 6e 63 6f 6e 2f 6d 61 69 6e 2e 67 6f } //5 cs_gencon/main.go
		$a_00_2 = {72 75 6e 74 69 6d 65 2e 70 65 72 73 69 73 74 65 6e 74 61 6c 6c 6f 63 } //1 runtime.persistentalloc
		$a_00_3 = {70 72 6f 63 65 73 73 29 2e 6b 69 6c 6c } //1 process).kill
	condition:
		((#a_02_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=7
 
}