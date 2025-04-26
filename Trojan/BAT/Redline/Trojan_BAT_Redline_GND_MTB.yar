
rule Trojan_BAT_Redline_GND_MTB{
	meta:
		description = "Trojan:BAT/Redline.GND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {67 30 68 34 69 35 6a 38 6b 45 6c 55 6d 58 6f } //g0h4i5j8kElUmXo  1
		$a_80_1 = {71 64 72 73 73 74 78 75 } //qdrsstxu  1
		$a_80_2 = {43 42 48 47 49 47 4f 4e 50 4e 56 55 } //CBHGIGONPNVU  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}