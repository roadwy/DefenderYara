
rule Trojan_BAT_Injuke_SWA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 06 08 09 6f 4c 00 00 0a 13 04 08 11 04 58 0c 09 11 04 59 0d 09 16 3d e4 ff ff ff dd 0d 00 00 00 07 39 06 00 00 00 07 6f 8a 00 00 0a dc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}