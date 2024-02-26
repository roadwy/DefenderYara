
rule Trojan_Win32_Jaik_GMX_MTB{
	meta:
		description = "Trojan:Win32/Jaik.GMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {03 7a 5b 6b f4 f5 18 6d 66 } //0a 00 
		$a_03_1 = {08 5d 2c 7d 90 01 01 0b 96 90 01 04 53 14 e7 32 6b 77 b9 90 01 04 2d 90 00 } //01 00 
		$a_01_2 = {62 30 35 6a 6e 6c 79 67 6a } //00 00  b05jnlygj
	condition:
		any of ($a_*)
 
}