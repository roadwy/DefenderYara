
rule Trojan_Win32_Redline_GWZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GWZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 74 24 20 c1 ea ?? 0f be 5c 15 ?? 6b db 57 b8 ?? ?? ?? ?? f7 eb 89 d0 c1 f8 04 c1 fb 1f 29 d8 ba ?? ?? ?? ?? 0f af c2 30 04 0e 83 c1 ?? 39 f9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}