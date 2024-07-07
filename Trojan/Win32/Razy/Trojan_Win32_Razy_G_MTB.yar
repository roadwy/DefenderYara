
rule Trojan_Win32_Razy_G_MTB{
	meta:
		description = "Trojan:Win32/Razy.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {21 c0 31 1a 42 81 c0 90 01 04 29 c8 39 fa 75 df c3 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}