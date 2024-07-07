
rule Trojan_BAT_RedLine_RDP_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 70 49 49 46 72 46 70 68 72 6e 6f 67 } //1 epIIFrFphrnog
		$a_01_1 = {62 30 62 36 61 61 65 38 2d 39 63 37 64 2d 34 36 38 33 2d 61 61 66 38 2d 33 34 32 39 62 62 35 65 64 38 65 36 } //1 b0b6aae8-9c7d-4683-aaf8-3429bb5ed8e6
		$a_01_2 = {51 6b 6b 62 61 6c } //1 Qkkbal
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}