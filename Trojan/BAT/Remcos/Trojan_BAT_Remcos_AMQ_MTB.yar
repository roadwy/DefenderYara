
rule Trojan_BAT_Remcos_AMQ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 08 09 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 7e 90 01 03 04 06 28 90 01 03 06 d2 9c 09 17 58 90 00 } //2
		$a_01_1 = {50 00 72 00 6f 00 74 00 6f 00 74 00 79 00 70 00 65 00 } //1 Prototype
		$a_01_2 = {55 59 52 30 30 31 30 34 35 33 } //1 UYR0010453
		$a_01_3 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}