
rule Trojan_Win32_Midie_NM_MTB{
	meta:
		description = "Trojan:Win32/Midie.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {68 a0 0f 00 00 ff 30 83 c7 90 01 01 e8 22 17 00 00 59 59 85 c0 74 0c 46 83 fe 90 01 01 7c d2 33 c0 90 00 } //01 00 
		$a_01_1 = {4d 00 4a 00 50 00 47 00 43 00 2e 00 54 00 4d 00 50 00 } //00 00  MJPGC.TMP
	condition:
		any of ($a_*)
 
}