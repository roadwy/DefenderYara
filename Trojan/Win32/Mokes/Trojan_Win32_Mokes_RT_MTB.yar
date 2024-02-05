
rule Trojan_Win32_Mokes_RT_MTB{
	meta:
		description = "Trojan:Win32/Mokes.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 ec 04 08 00 00 a1 90 01 04 33 c4 89 84 24 90 01 04 56 33 f6 85 db 7e 90 01 01 e8 90 01 04 30 04 37 83 fb 19 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Mokes_RT_MTB_2{
	meta:
		description = "Trojan:Win32/Mokes.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 c7 05 90 01 04 36 06 ea e9 8b 4d 90 01 01 33 4d 90 01 01 89 4d 90 01 01 81 3d 90 02 08 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Mokes_RT_MTB_3{
	meta:
		description = "Trojan:Win32/Mokes.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 c7 05 90 01 04 84 10 d6 cb c7 05 90 01 04 ff ff ff ff 89 44 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 81 3d 90 01 04 c6 0e 00 00 75 90 01 01 55 55 ff 15 90 01 04 8b 4c 24 90 01 01 33 cf 33 ce 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}