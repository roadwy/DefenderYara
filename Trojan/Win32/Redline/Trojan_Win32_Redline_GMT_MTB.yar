
rule Trojan_Win32_Redline_GMT_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f0 8b c6 c1 e8 0d 33 c6 69 c8 90 01 04 8b c1 c1 e8 0f 33 c1 3b 44 24 48 90 01 02 8b 44 24 10 8b 4c 24 38 83 c0 04 89 44 24 10 83 f9 10 90 01 02 8b 54 24 24 41 8b c2 81 f9 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}