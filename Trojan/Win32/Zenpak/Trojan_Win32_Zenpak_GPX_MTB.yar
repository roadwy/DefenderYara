
rule Trojan_Win32_Zenpak_GPX_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 55 fa 0f b6 75 fb 31 f2 88 d0 0f b6 c0 83 c4 04 5e 5d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}