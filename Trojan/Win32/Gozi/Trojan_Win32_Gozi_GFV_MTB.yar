
rule Trojan_Win32_Gozi_GFV_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d0 0f b6 30 8b 4d e4 ba ?? ?? ?? ?? 89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 c1 e0 ?? 01 d0 29 c1 89 ca 8b 45 e0 01 d0 0f b6 00 31 f0 88 03 83 45 e4 01 8b 55 e4 8b 45 c4 39 c2 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}