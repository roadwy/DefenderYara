
rule Trojan_Win32_Redline_GUF_MTB{
	meta:
		description = "Trojan:Win32/Redline.GUF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 00 0f be c0 69 c8 ?? ?? ?? ?? ba ?? ?? ?? ?? 89 c8 f7 ea 8d 04 0a c1 f8 ?? 89 c2 89 c8 c1 f8 ?? 29 c2 89 d0 89 c2 89 d0 c1 e0 ?? 29 d0 89 c1 8b 55 ?? 8b 45 ?? 01 d0 31 cb 89 da 88 10 83 45 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}