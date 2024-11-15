
rule Trojan_Win32_Guloader_KAD_MTB{
	meta:
		description = "Trojan:Win32/Guloader.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {6d 69 6c 69 74 61 72 69 73 74 65 72 6e 65 2e 73 6d 6f } //militaristerne.smo  1
		$a_80_1 = {6d 6f 6d 65 6e 74 76 69 73 2e 66 69 6e } //momentvis.fin  1
		$a_80_2 = {41 6e 74 69 64 65 72 69 76 61 74 69 76 65 } //Antiderivative  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}