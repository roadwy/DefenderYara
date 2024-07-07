
rule Trojan_BAT_Nanocore_WGN_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.WGN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 8e 69 5d 91 61 02 } //1
		$a_01_1 = {17 d6 02 8e 69 5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}