
rule Trojan_BAT_Clipbanker_MCT_MTB{
	meta:
		description = "Trojan:BAT/Clipbanker.MCT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 11 05 02 11 05 91 07 11 05 1a 5d 1e 5a 1f 1f 5f 64 d2 61 d2 9c 06 11 05 91 2d 0f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}