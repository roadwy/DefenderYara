
rule Trojan_Win32_Redline_DJST_MTB{
	meta:
		description = "Trojan:Win32/Redline.DJST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 8d 45 08 50 e8 ?? ?? ?? ?? 8b 45 ?? 33 45 ?? 68 ?? ?? ?? ?? 2b f8 8d 45 ?? 50 e8 ?? ?? ?? ?? ff 4d ?? 0f 85 } //1
		$a_00_1 = {31 08 83 c5 70 c9 c2 08 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}