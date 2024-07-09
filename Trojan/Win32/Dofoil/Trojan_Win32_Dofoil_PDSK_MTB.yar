
rule Trojan_Win32_Dofoil_PDSK_MTB{
	meta:
		description = "Trojan:Win32/Dofoil.PDSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 33 45 dc 89 45 fc c7 05 ?? ?? ?? ?? f4 6e e0 f7 8b 4d fc 33 4d f8 89 4d f8 8b 55 f4 2b 55 f8 89 55 f4 81 3d ?? ?? ?? ?? d9 02 00 00 75 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}