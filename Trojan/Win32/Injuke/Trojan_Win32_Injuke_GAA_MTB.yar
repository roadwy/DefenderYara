
rule Trojan_Win32_Injuke_GAA_MTB{
	meta:
		description = "Trojan:Win32/Injuke.GAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2a 01 00 00 00 d6 02 2c 00 73 90 01 01 28 00 00 da 0a 00 73 90 01 01 0d ca 0b 3b 28 00 00 2a 01 00 fd 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}