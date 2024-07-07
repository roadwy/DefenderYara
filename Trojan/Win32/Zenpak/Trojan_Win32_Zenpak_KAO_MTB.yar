
rule Trojan_Win32_Zenpak_KAO_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.KAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 55 fa 0f b6 75 fb 31 f2 88 d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}