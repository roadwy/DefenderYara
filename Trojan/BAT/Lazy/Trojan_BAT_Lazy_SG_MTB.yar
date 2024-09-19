
rule Trojan_BAT_Lazy_SG_MTB{
	meta:
		description = "Trojan:BAT/Lazy.SG!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 57 5f 48 49 44 45 } //1 SW_HIDE
		$a_01_1 = {65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 5f 00 6b 00 65 00 79 00 } //1 encrypted_key
		$a_01_2 = {2f 00 2f 00 61 00 70 00 69 00 2e 00 67 00 6f 00 66 00 69 00 6c 00 65 00 2e 00 69 00 6f 00 2f 00 67 00 65 00 74 00 53 00 65 00 72 00 76 00 65 00 72 00 } //3 //api.gofile.io/getServer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=5
 
}