
rule Trojan_Win32_Redline_JAH_MTB{
	meta:
		description = "Trojan:Win32/Redline.JAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 0c 10 c1 e1 08 33 4d f8 89 4d f8 ba 01 00 00 00 6b c2 00 8b 4d e8 0f be 14 01 33 55 f8 89 55 f8 69 45 f8 ?? ?? ?? ?? 89 45 f8 8b 4d fc 33 4d f8 89 4d fc 8b 55 fc c1 ea 0d 33 55 fc 89 55 fc 69 45 fc ?? ?? ?? ?? 89 45 fc 8b 4d fc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}