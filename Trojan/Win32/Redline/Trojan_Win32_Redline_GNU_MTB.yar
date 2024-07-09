
rule Trojan_Win32_Redline_GNU_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 06 59 59 0f b6 0f 03 c8 0f b6 c1 8b 4c 24 ?? 8a 84 04 ?? ?? ?? ?? 30 85 ?? ?? ?? ?? 45 81 fd } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNU_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 80 34 1f ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 80 04 1f ?? 83 c4 40 68 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNU_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GNU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 f0 56 57 e8 ?? ?? ?? ?? 0f b6 06 83 c4 ?? 0f b6 0f 03 c8 0f b6 c1 8b 4c 24 ?? 8a 84 04 ?? ?? ?? ?? 30 85 ?? ?? ?? ?? 45 81 fd } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}