
rule Trojan_Win32_LummaStealer_NM_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {8b 35 08 91 75 00 8d 4f 90 01 01 03 74 24 18 ba 90 01 04 8b 5e 04 2b f7 90 00 } //03 00 
		$a_03_1 = {8b 04 0e 8d 49 90 01 01 03 c3 89 41 fc 83 ea 01 75 f0 a1 0c 91 75 00 89 47 08 8d 44 24 10 90 00 } //01 00 
		$a_01_2 = {47 61 6d 65 4a 61 63 6b } //00 00  GameJack
	condition:
		any of ($a_*)
 
}