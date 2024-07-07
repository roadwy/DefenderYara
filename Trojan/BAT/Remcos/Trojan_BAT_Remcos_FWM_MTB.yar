
rule Trojan_BAT_Remcos_FWM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.FWM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {09 08 11 04 08 8e 69 5d 91 06 11 04 91 61 d2 6f 90 01 03 0a 90 00 } //2
		$a_01_1 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_2 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}