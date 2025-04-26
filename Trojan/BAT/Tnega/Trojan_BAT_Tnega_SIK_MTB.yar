
rule Trojan_BAT_Tnega_SIK_MTB{
	meta:
		description = "Trojan:BAT/Tnega.SIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 78 69 61 6e 67 67 72 68 65 6e 2e 63 6f 6d 2f 63 6f 6d 70 6f 73 75 72 65 2f } //1 http://xianggrhen.com/composure/
		$a_81_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}