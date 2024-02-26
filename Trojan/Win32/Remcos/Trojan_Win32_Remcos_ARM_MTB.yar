
rule Trojan_Win32_Remcos_ARM_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 f0 8b 44 24 20 8b d0 03 f7 0b 54 24 24 23 54 24 28 23 44 24 24 0b d0 03 d6 8b 44 24 30 8b 74 24 14 83 c0 20 89 44 24 30 3d 00 01 00 00 8b 44 24 10 89 54 24 2c 89 54 24 34 } //00 00 
	condition:
		any of ($a_*)
 
}