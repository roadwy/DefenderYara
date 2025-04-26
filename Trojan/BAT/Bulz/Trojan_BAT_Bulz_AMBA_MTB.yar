
rule Trojan_BAT_Bulz_AMBA_MTB{
	meta:
		description = "Trojan:BAT/Bulz.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {11 07 11 01 03 11 01 91 11 03 61 d2 9c 38 } //1
		$a_01_1 = {11 02 11 09 11 01 94 58 11 05 11 01 94 58 20 00 01 00 00 5d 13 02 } //1
		$a_01_2 = {11 09 11 09 11 00 94 11 09 11 02 94 58 20 00 01 00 00 5d 94 13 03 } //1
		$a_80_3 = {49 66 6d 7a 75 78 70 64 71 63 74 6d 71 6e } //Ifmzuxpdqctmqn  1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}