
rule Trojan_Win32_Farfli_AZ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {0f b6 08 33 ca 8b 55 08 03 55 f4 88 0a 66 8b 45 fc 66 83 c0 01 66 89 45 fc eb b3 } //02 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00  VirtualAlloc
	condition:
		any of ($a_*)
 
}