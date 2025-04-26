
rule Trojan_Win32_Redline_GNL_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 10 8b c8 6a 01 ff 12 ff 74 24 ?? 8b cf e8 ?? ?? ?? ?? 8b cf e8 ?? ?? ?? ?? 8a 84 1c ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 46 8b 5c 24 ?? 8b 54 24 ?? 81 fe 00 b2 02 00 0f 82 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}