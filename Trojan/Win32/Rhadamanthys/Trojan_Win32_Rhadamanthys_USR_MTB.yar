
rule Trojan_Win32_Rhadamanthys_USR_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.USR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 f0 8a 16 02 f2 0f b6 c6 03 c8 0f b6 01 88 06 88 11 0f b6 06 0f b6 ca 03 c8 0f b6 c1 8b 8d 90 01 04 0f b6 84 05 90 01 04 30 04 0f 47 3b bd 90 01 04 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}