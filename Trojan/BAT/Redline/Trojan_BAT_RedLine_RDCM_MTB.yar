
rule Trojan_BAT_RedLine_RDCM_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDCM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 63 63 36 31 30 35 65 2d 35 31 30 30 2d 34 33 34 38 2d 62 34 66 61 2d 36 34 63 65 39 61 34 62 32 64 66 66 } //1 bcc6105e-5100-4348-b4fa-64ce9a4b2dff
		$a_01_1 = {43 68 72 6f 6d 65 } //1 Chrome
		$a_01_2 = {48 62 6e 70 6b 78 } //1 Hbnpkx
		$a_01_3 = {6c 46 42 79 } //1 lFBy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}