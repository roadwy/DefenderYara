
rule PWS_Win32_Racealer_KM_MTB{
	meta:
		description = "PWS:Win32/Racealer.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 39 1d 90 01 04 76 90 01 01 8b 0d 90 01 04 8a 8c 01 90 01 04 8b 15 90 01 04 88 0c 02 8b 0d 90 01 04 81 f9 03 02 00 00 75 90 01 01 89 1d 90 01 04 40 3b c1 72 90 00 } //01 00 
		$a_00_1 = {30 04 37 83 fb 19 75 } //00 00 
	condition:
		any of ($a_*)
 
}