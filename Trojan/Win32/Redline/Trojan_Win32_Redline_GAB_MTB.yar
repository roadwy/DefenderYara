
rule Trojan_Win32_Redline_GAB_MTB{
	meta:
		description = "Trojan:Win32/Redline.GAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 a3 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 c2 80 30 ?? 8d 8d ?? ?? ?? ?? 51 ff d6 01 3d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 74 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}