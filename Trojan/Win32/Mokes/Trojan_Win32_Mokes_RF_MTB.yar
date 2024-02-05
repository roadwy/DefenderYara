
rule Trojan_Win32_Mokes_RF_MTB{
	meta:
		description = "Trojan:Win32/Mokes.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b ec 81 ec 04 08 00 00 a1 90 01 04 33 c5 89 45 90 01 01 56 33 f6 85 db 7e 90 01 01 e8 90 01 04 30 04 37 83 fb 19 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}