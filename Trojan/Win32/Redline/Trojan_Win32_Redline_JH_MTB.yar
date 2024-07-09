
rule Trojan_Win32_Redline_JH_MTB{
	meta:
		description = "Trojan:Win32/Redline.JH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 04 3b 45 10 0f 83 ?? ?? ?? ?? 8b 45 08 89 04 24 8b 44 24 04 31 d2 f7 75 14 8b 04 24 c1 ea 02 0f be 04 10 6b c0 48 6b c0 4f 6b f0 4b 8b 45 0c 8b 4c 24 04 0f be 14 08 31 f2 88 14 08 8b 44 24 04 83 c0 01 89 44 24 04 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}