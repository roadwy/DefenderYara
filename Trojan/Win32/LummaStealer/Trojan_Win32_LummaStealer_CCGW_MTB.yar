
rule Trojan_Win32_LummaStealer_CCGW_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCGW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 d1 41 ff e1 31 c9 3d 90 01 04 0f 9c c1 8b 0c 8d 90 01 04 ba 90 01 04 33 15 90 01 04 01 d1 41 ff e1 31 c9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}