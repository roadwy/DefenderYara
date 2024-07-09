
rule Trojan_Win32_Redline_GXQ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GXQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 37 34 ?? 2c ?? 6a 00 88 04 37 ff 15 ?? ?? ?? ?? 8a 04 37 2c ?? 34 ?? 04 ?? 34 ?? 2c ?? 34 ?? 2c ?? 34 ?? 88 04 37 46 3b 74 24 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}