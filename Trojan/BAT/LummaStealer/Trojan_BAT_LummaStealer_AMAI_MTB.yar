
rule Trojan_BAT_LummaStealer_AMAI_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.AMAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 08 03 08 03 8e 69 5d 91 9c 08 17 58 0c } //1
		$a_03_1 = {91 61 d2 81 [0-1e] 02 8e 69 3f } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}