
rule Trojan_Win32_Redline_GXN_MTB{
	meta:
		description = "Trojan:Win32/Redline.GXN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 8b 7c 24 ?? 39 74 24 ?? ?? ?? 80 34 37 ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8a 04 37 2c ?? 34 ?? 04 ?? 34 ?? 2c ?? 34 ?? 2c ?? 34 ?? 88 04 37 46 3b 74 24 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}