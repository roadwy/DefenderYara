
rule Trojan_BAT_PrivateLoader_RDK_MTB{
	meta:
		description = "Trojan:BAT/PrivateLoader.RDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 3d 00 00 0a 28 3e 00 00 0a 1a 8d 1e 00 00 01 25 16 28 3f 00 00 0a a2 25 17 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}