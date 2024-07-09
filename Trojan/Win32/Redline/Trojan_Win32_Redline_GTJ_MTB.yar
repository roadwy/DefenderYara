
rule Trojan_Win32_Redline_GTJ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 5c 15 00 6b db ?? b8 ?? ?? ?? ?? f7 eb 89 d0 c1 f8 ?? c1 fb ?? 29 d8 ba ?? ?? ?? ?? 0f af c2 30 04 0e 83 c1 ?? 39 f9 75 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}