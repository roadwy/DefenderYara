
rule Trojan_Win32_Zenpak_SPA_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.SPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 45 0c 8a 4d 08 88 45 fb 88 4d fa 8b 15 90 01 04 81 c2 90 01 04 89 15 90 01 04 0f b6 55 fa 0f b6 75 fb 31 f2 88 d0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}