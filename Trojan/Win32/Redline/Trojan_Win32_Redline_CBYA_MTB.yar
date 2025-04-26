
rule Trojan_Win32_Redline_CBYA_MTB{
	meta:
		description = "Trojan:Win32/Redline.CBYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 ff b4 0e ?? ?? ?? ?? 8b 84 0e ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 8b 84 0e ?? ?? ?? ?? 03 c2 50 ff b5 9c fd ff ff ff 95 88 fd ff ff 0f b7 87 ?? ?? ?? ?? 8d 76 28 8b 95 94 fd ff ff 43 3b d8 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}