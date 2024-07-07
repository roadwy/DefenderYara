
rule Trojan_Win32_Tnega_XO_MTB{
	meta:
		description = "Trojan:Win32/Tnega.XO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {ba 3d 24 00 00 e9 } //1
		$a_01_1 = {be 3f 10 10 28 e9 } //1
		$a_01_2 = {31 34 81 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}