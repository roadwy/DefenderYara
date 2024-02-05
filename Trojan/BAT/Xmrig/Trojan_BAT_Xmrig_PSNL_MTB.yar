
rule Trojan_BAT_Xmrig_PSNL_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.PSNL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {72 d3 6c 00 70 14 28 7e 00 00 06 1c 2d 17 26 28 88 00 00 0a 28 39 02 00 06 74 5b 00 00 1b 6f 89 00 00 0a 2b 07 28 8a 00 00 0a 2b e3 2a } //00 00 
	condition:
		any of ($a_*)
 
}