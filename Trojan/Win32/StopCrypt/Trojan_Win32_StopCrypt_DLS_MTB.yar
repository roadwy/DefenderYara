
rule Trojan_Win32_StopCrypt_DLS_MTB{
	meta:
		description = "Trojan:Win32/StopCrypt.DLS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {d3 ea 8d 04 37 89 45 e8 c7 05 f8 b5 a9 02 ee 3d ea f4 03 55 d4 8b 45 e8 31 45 fc 33 55 fc 81 3d 60 c0 a9 02 13 02 00 00 89 55 e8 } //00 00 
	condition:
		any of ($a_*)
 
}