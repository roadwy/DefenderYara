
rule Trojan_BAT_Wagex_GFM_MTB{
	meta:
		description = "Trojan:BAT/Wagex.GFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {38 30 2e 36 36 2e 37 35 2e 33 36 } //80.66.75.36  1
		$a_80_1 = {4e 71 6a 72 6e 66 77 78 } //Nqjrnfwx  1
		$a_01_2 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_80_3 = {4e 74 70 77 6f 67 74 69 74 79 61 69 71 68 79 70 70 6c 67 64 67 6b } //Ntpwogtityaiqhypplgdgk  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}