
rule Trojan_Win32_Zenpak_CCAS_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CCAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 f4 0f b7 80 90 01 04 89 45 dc 8b 45 dc 33 45 e0 89 45 e0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}