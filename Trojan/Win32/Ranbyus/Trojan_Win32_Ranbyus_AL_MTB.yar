
rule Trojan_Win32_Ranbyus_AL_MTB{
	meta:
		description = "Trojan:Win32/Ranbyus.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b6 4c 14 90 01 01 4b 30 4f 90 01 01 47 2b dd 59 29 1d 90 02 04 8d 5a 90 01 01 4d 0f 85 90 00 } //02 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00 
	condition:
		any of ($a_*)
 
}