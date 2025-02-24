
rule Trojan_Win64_Zusy_YAF_MTB{
	meta:
		description = "Trojan:Win64/Zusy.YAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_03_0 = {6b c6 04 d9 9c 28 90 90 fe ff ff ff c6 e9 ?? ?? ?? ?? d8 f7 93 } //8
		$a_01_1 = {c8 80 00 00 48 81 ec } //1
		$a_01_2 = {9b db e3 e9 cc 6f fd ff } //1
		$a_03_3 = {ad 48 83 ee 03 35 ?? ?? ?? ?? e9 ?? ?? ?? ?? 52 02 ef 2d } //1
	condition:
		((#a_03_0  & 1)*8+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=11
 
}