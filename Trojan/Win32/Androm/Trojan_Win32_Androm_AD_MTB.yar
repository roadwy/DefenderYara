
rule Trojan_Win32_Androm_AD_MTB{
	meta:
		description = "Trojan:Win32/Androm.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 4d ff bf b4 53 40 00 88 4d e0 83 c9 ff 33 c0 89 75 e4 f2 ae f7 d1 49 89 75 e8 51 68 b4 53 40 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}