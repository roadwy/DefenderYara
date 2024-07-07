
rule Trojan_Win32_UniCube_MA_MTB{
	meta:
		description = "Trojan:Win32/UniCube.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 99 be e8 03 00 00 f7 fe 89 44 24 1c 3b d9 7e 90 01 01 8d a4 24 00 00 00 00 8a 44 24 1c f6 e9 02 c2 28 04 29 41 3b cb 7c 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}