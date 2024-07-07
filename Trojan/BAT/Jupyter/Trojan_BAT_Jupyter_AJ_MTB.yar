
rule Trojan_BAT_Jupyter_AJ_MTB{
	meta:
		description = "Trojan:BAT/Jupyter.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 15 13 0a 2b 28 11 09 7e 08 00 00 04 1a 9a 11 0a 17 da 17 6f 39 00 00 0a 28 3c 00 00 0a 28 3d 00 00 0a 6f 3e 00 00 0a 11 0a 17 d6 13 0a 11 0a 11 15 31 d2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}