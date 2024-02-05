
rule Trojan_Win32_LummaStealer_CCAK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 c8 31 d2 f7 f7 0f b7 44 4d 00 66 33 04 53 66 89 44 4d 00 41 39 f1 7c } //00 00 
	condition:
		any of ($a_*)
 
}