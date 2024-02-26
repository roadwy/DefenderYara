
rule Trojan_Win32_Stealc_NCS_MTB{
	meta:
		description = "Trojan:Win32/Stealc.NCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {75 05 e8 e1 1e 00 00 8b 35 90 01 04 33 ff 8a 06 3a c3 74 12 3c 90 01 01 74 01 47 56 e8 f5 f5 ff ff 59 8d 74 06 90 01 01 eb e8 8d 04 bd 90 00 } //01 00 
		$a_01_1 = {76 63 61 70 69 2e 65 78 65 } //00 00  vcapi.exe
	condition:
		any of ($a_*)
 
}