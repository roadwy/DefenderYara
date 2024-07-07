
rule Trojan_AndroidOS_Brokewell_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Brokewell.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 77 65 62 76 2f 64 75 6d 70 2d 63 6f 6f 6b 69 65 73 } //1 /webv/dump-cookies
		$a_01_1 = {61 73 6b 4c 4f 43 4b 50 49 4e } //1 askLOCKPIN
		$a_01_2 = {57 65 62 76 49 6e 6a 65 63 74 } //1 WebvInject
		$a_01_3 = {74 61 6b 65 53 63 72 65 65 6e 73 68 6f 74 } //1 takeScreenshot
		$a_01_4 = {63 6f 6d 2f 62 72 6b 77 6c 2f 75 70 73 74 72 61 63 6b 69 6e 67 2f 53 63 52 65 63 53 72 76 63 } //1 com/brkwl/upstracking/ScRecSrvc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}