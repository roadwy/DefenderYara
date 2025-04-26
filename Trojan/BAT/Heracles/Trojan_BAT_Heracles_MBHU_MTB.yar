
rule Trojan_BAT_Heracles_MBHU_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 66 00 69 00 6c 00 65 00 5c 00 73 00 61 00 6d 00 2e 00 7a 00 69 00 70 00 } //1 C:\file\sam.zip
		$a_01_1 = {70 00 72 00 6f 00 74 00 65 00 63 00 74 00 2e 00 7a 00 69 00 70 00 } //1 protect.zip
		$a_01_2 = {77 00 65 00 6c 00 77 00 6b 00 64 00 71 00 69 00 75 00 77 00 7a 00 78 00 70 00 72 00 6b 00 77 00 } //1 welwkdqiuwzxprkw
		$a_01_3 = {72 00 61 00 6d 00 61 00 64 00 61 00 6e 00 33 00 38 00 } //1 ramadan38
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}