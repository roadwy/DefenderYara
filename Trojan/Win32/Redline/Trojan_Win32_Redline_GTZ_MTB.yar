
rule Trojan_Win32_Redline_GTZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 f0 0f b6 1c 37 c1 e8 ?? 0f be 88 ?? ?? ?? ?? 6b c9 ?? b8 ?? ?? ?? ?? f7 e9 01 ca c1 f9 ?? c1 fa ?? 29 d1 c1 e1 ?? 31 d9 88 0c 37 83 c6 ?? 83 fe } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}