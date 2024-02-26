
rule Trojan_Win32_LummaStealer_ME_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 c1 f6 d1 80 c9 61 00 c8 04 9f 20 c8 f6 d0 a2 } //01 00 
		$a_01_1 = {89 c1 83 c1 01 89 0f 0f b6 00 8b 55 ec 8b 0a 8b 75 f0 89 04 8e 8b 07 89 c1 83 c1 01 89 0f 0f b6 00 c1 e0 08 8b 0a 8b 14 8e 89 c6 } //00 00 
	condition:
		any of ($a_*)
 
}