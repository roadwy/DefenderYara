
rule Trojan_Win16_Emotet_DD{
	meta:
		description = "Trojan:Win16/Emotet.DD,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {75 72 6c 6d } //1 urlm
		$a_00_1 = {6f 6e 22 2c 22 75 72 6c 64 6f 77 6e 6c 6f 61 64 74 6f 66 69 6c } //1 on","urldownloadtofil
		$a_00_2 = {6a 6a 63 63 62 62 } //1 jjccbb
		$a_00_3 = {2e 6f 63 78 } //1 .ocx
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}