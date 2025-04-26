
rule Trojan_Win32_Fareit_FF_MTB{
	meta:
		description = "Trojan:Win32/Fareit.FF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 84 85 e4 fb ff ff 33 d2 8a 55 f7 33 c2 3d ?? ?? ?? ?? 76 ?? e8 ?? ?? ?? ?? 8b 55 e8 88 02 ?? 47 ff 4d e4 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}