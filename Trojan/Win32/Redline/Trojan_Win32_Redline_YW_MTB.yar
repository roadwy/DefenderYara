
rule Trojan_Win32_Redline_YW_MTB{
	meta:
		description = "Trojan:Win32/Redline.YW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 89 45 ec 8b 45 f0 31 d2 f7 75 14 8b 45 ec c1 ea 02 0f be 04 10 6b c0 57 b9 ?? ?? ?? ?? 99 f7 f9 6b c0 3d 6b c0 22 6b f0 41 8b 45 0c 8b 4d f0 0f be 14 08 31 f2 88 14 08 8b 45 f0 83 c0 01 89 45 f0 e9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}