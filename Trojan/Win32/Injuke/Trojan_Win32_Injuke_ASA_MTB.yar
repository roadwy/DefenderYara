
rule Trojan_Win32_Injuke_ASA_MTB{
	meta:
		description = "Trojan:Win32/Injuke.ASA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {2a 01 00 00 00 be [0-04] 2d 79 00 00 da 0a 00 73 5b 0d ca 1b f0 78 } //5
		$a_01_1 = {2a 01 00 00 00 5a 05 7c 00 f7 63 78 00 00 da 0a 00 73 5b 0d ca b3 26 78 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}