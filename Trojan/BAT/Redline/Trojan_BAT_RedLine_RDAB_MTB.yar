
rule Trojan_BAT_RedLine_RDAB_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 63 72 6a 70 65 6f 6d 67 6b 6d 6d 62 } //1 rcrjpeomgkmmb
		$a_01_1 = {26 17 58 7d c3 00 00 04 07 03 1e 63 d2 9c } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}