
rule Trojan_MacOS_Rustbucket_AS{
	meta:
		description = "Trojan:MacOS/Rustbucket.AS,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 73 6f 66 74 77 61 72 65 64 65 76 2e 73 77 69 66 74 2d 75 69 2d 74 65 73 74 } //1 com.softwaredev.swift-ui-test
		$a_00_1 = {37 4c 32 55 51 54 56 50 36 46 } //1 7L2UQTVP6F
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}