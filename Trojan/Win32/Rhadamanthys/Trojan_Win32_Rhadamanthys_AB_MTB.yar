
rule Trojan_Win32_Rhadamanthys_AB_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 44 0c 04 88 44 24 03 89 fb 00 c3 89 c8 31 d2 f7 b4 24 24 01 00 00 02 5c 15 00 89 df 0f b6 c3 0f b6 5c 24 03 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}