
rule Trojan_Win32_Redline_GTD_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f8 8a 14 11 80 f2 42 88 14 01 41 3b 4d fc ?? ?? 8b 4d fc 50 88 1c 08 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GTD_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be c0 69 c8 ?? ?? ?? ?? ba ?? ?? ?? ?? 89 c8 f7 ea 8d 04 0a c1 f8 ?? 89 c2 89 c8 c1 f8 ?? 29 c2 89 d0 ba ?? ?? ?? ?? 0f af c2 89 c1 8b 55 f0 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 f0 01 eb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}