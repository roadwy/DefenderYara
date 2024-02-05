
rule Trojan_Win32_Mokes_PVD_MTB{
	meta:
		description = "Trojan:Win32/Mokes.PVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {25 ff 00 00 00 8a 98 90 01 04 88 90 01 05 88 99 90 01 04 0f b6 90 01 05 a3 90 01 04 0f b6 c3 03 d0 81 e2 ff 00 00 00 8a 8a 90 01 04 30 0c 37 90 00 } //02 00 
		$a_02_1 = {25 ff 00 00 00 8a 98 90 01 04 88 90 01 05 a3 90 01 04 88 99 58 31 84 00 0f b6 80 90 01 04 0f b6 cb 03 c1 25 ff 00 00 00 0f b6 90 01 05 30 14 3e 90 00 } //02 00 
		$a_02_2 = {25 ff 00 00 00 8a 98 90 01 04 88 90 01 05 88 99 90 01 04 0f b6 90 01 05 89 0d 90 01 04 0f b6 cb 03 ca 81 e1 ff 00 00 00 a3 90 01 04 8a 81 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}