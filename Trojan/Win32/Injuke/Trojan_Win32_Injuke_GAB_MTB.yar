
rule Trojan_Win32_Injuke_GAB_MTB{
	meta:
		description = "Trojan:Win32/Injuke.GAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2a 01 00 00 00 fe 58 2f 00 9b 90 01 04 da 0a 00 73 5b 0d ca 36 91 2b 00 00 d4 00 00 f3 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}