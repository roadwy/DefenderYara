
rule Trojan_Win32_Emotet_ARK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.ARK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 00 8d 6d 04 33 cf 0f b6 c1 66 89 06 8b c1 c1 e8 08 [0-1f] c1 e9 10 0f b6 c1 c1 e9 08 43 [0-0f] 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}