
rule Trojan_BAT_Spy_Noon_AL{
	meta:
		description = "Trojan:BAT/Spy.Noon.AL!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 02 6f 53 00 00 0a 00 02 18 5d 16 fe 01 0c 08 2c 17 02 6c 23 00 00 00 00 00 00 00 40 5b 28 55 00 00 0a b7 10 00 00 2b 09 00 19 02 d8 17 d6 10 00 00 00 02 17 fe 01 16 fe 01 0d 09 2d c2 07 02 6f 53 00 00 0a 00 07 0a 2b 00 06 2a } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}