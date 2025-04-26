
rule Trojan_Win32_Redline_GTH_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be c0 6b c8 57 ba ?? ?? ?? ?? 89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 ba ?? ?? ?? ?? 0f af c2 89 c1 8b 55 f0 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 f0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}