
rule Trojan_Win32_Zenpak_KAI_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.KAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 75 00 66 0f b3 e9 80 f5 9a 8a 06 0f 95 c1 00 d8 0f 9c c5 46 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}