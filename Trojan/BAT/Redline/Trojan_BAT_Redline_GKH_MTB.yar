
rule Trojan_BAT_Redline_GKH_MTB{
	meta:
		description = "Trojan:BAT/Redline.GKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {06 07 91 0d 06 07 06 08 91 9c 06 08 09 d2 9c 07 17 58 0b 08 17 59 0c 07 08 32 e5 06 2a } //00 00 
	condition:
		any of ($a_*)
 
}