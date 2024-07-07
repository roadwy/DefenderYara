
rule Trojan_Win32_Redline_GDE_MTB{
	meta:
		description = "Trojan:Win32/Redline.GDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 83 e0 90 01 01 51 51 f2 0f 11 04 24 8a 98 90 01 04 32 1c 2e e8 90 01 04 83 c4 08 88 1c 2e 46 dd d8 3b f7 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}