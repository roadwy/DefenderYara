
rule Trojan_Win32_Fauppod_ME_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {54 65 72 63 76 4f 69 6d 6e 75 79 } //02 00  TercvOimnuy
		$a_01_1 = {54 72 63 74 76 79 62 4b 75 6e 62 79 } //02 00  TrctvybKunby
		$a_01_2 = {4f 6e 75 62 79 76 44 74 63 76 79 62 } //01 00  OnubyvDtcvyb
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 45 78 } //00 00  WaitForSingleObjectEx
	condition:
		any of ($a_*)
 
}