
rule Trojan_BAT_XWorm_STUP_MTB{
	meta:
		description = "Trojan:BAT/XWorm.STUP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 3c 00 00 0a 0c 03 7e ?? 00 00 04 73 3d 00 00 0a 0d 08 09 1f 20 6f 3e 00 00 0a 6f 3f 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}