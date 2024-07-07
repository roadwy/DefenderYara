
rule Trojan_BAT_Injuke_MBYD_MTB{
	meta:
		description = "Trojan:BAT/Injuke.MBYD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 35 00 41 00 39 00 7e 00 33 00 7e 00 7c 00 30 00 34 00 7e 00 7c 00 46 00 46 00 46 00 46 00 7e 00 42 00 38 00 7e 00 7e 00 7e 00 7c 00 34 00 } //1 4D5A9~3~|04~|FFFF~B8~~~|4
	condition:
		((#a_01_0  & 1)*1) >=1
 
}