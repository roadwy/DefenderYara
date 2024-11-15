
rule Trojan_BAT_RedLineStealz_A_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealz.A!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 38 46 34 33 31 41 35 34 39 34 31 31 41 45 42 33 32 38 31 30 30 36 38 41 34 43 38 33 32 35 30 42 32 44 33 31 45 31 35 } //1 38F431A549411AEB32810068A4C83250B2D31E15
	condition:
		((#a_01_0  & 1)*1) >=1
 
}