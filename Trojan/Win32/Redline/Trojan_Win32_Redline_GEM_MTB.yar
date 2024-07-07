
rule Trojan_Win32_Redline_GEM_MTB{
	meta:
		description = "Trojan:Win32/Redline.GEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 d2 f7 75 14 8b 45 f4 0f be 04 10 6b c0 90 01 01 b9 90 01 04 99 f7 f9 6b c0 1d 6b f0 1b 8b 45 0c 8b 4d f8 0f b6 14 08 31 f2 88 14 08 8b 45 f8 83 c0 01 89 45 f8 e9 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}