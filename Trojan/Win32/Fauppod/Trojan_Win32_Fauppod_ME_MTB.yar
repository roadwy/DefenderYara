
rule Trojan_Win32_Fauppod_ME_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 65 72 63 76 4f 69 6d 6e 75 79 } //2 TercvOimnuy
		$a_01_1 = {54 72 63 74 76 79 62 4b 75 6e 62 79 } //2 TrctvybKunby
		$a_01_2 = {4f 6e 75 62 79 76 44 74 63 76 79 62 } //2 OnubyvDtcvyb
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 45 78 } //1 WaitForSingleObjectEx
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}