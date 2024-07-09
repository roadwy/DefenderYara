
rule Trojan_Win32_Redline_ASCB_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 80 34 1e ?? 83 c4 ?? 46 3b f7 0f } //1
		$a_03_1 = {ff 80 04 1e ?? 68 ?? ?? ?? 00 68 ?? ?? ?? 00 e8 ?? ?? ff ff 50 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}