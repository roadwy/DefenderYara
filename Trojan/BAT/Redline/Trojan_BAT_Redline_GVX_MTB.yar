
rule Trojan_BAT_Redline_GVX_MTB{
	meta:
		description = "Trojan:BAT/Redline.GVX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {02 06 58 0b 07 08 07 58 46 06 19 5d 17 58 61 52 06 17 58 0a 06 1f 12 32 e7 2a } //10
		$a_01_1 = {50 72 6f 6a 65 63 74 33 35 } //1 Project35
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}