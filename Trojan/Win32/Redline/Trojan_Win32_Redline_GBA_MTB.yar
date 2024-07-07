
rule Trojan_Win32_Redline_GBA_MTB{
	meta:
		description = "Trojan:Win32/Redline.GBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 d2 f7 75 14 8b 45 ec c1 ea 02 0f be 04 10 6b c0 90 01 01 b9 90 01 04 99 f7 f9 6b c0 90 01 01 6b c0 90 01 01 6b f0 90 01 01 8b 45 90 01 01 8b 4d 90 01 01 0f be 14 08 31 f2 88 14 08 8b 45 90 01 01 83 c0 90 01 01 89 45 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}