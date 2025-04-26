
rule Trojan_BAT_LummaStealer_SDE_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.SDE!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 25 11 27 37 09 11 2b 11 40 61 13 2c 2b 0a 11 3c 6e 11 29 6a 5b 6d 13 2c 11 31 6e 11 2b 6a 2f 09 11 42 11 3d 61 13 2b 2b 24 11 30 6e 11 22 6a 61 69 13 28 11 39 6e 11 36 6a 61 69 13 36 11 34 6e 11 23 6a 5b 26 11 20 6a 11 27 6e 5b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}