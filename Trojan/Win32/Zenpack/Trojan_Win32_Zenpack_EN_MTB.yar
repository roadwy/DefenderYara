
rule Trojan_Win32_Zenpack_EN_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_03_0 = {b9 03 00 00 00 55 8f 05 90 01 04 89 f8 01 05 90 01 04 e2 d0 31 c0 40 c3 89 45 00 d0 d0 d0 d0 d0 d0 d0 d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpack_EN_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpack.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 6f 67 65 74 68 65 72 4c 69 67 68 74 53 75 62 64 75 65 2e 57 61 70 70 65 61 72 } //01 00  togetherLightSubdue.Wappear
		$a_01_1 = {49 4d 6f 76 69 6e 67 2e 68 65 61 76 65 6e 70 75 6d } //01 00  IMoving.heavenpum
		$a_01_2 = {47 42 6b 57 5a 6d 65 61 74 44 6d } //01 00  GBkWZmeatDm
		$a_01_3 = {77 38 54 41 62 6f 76 65 4a 56 69 6e 6d 61 64 65 6f 77 6e 2e 6d 61 79 } //01 00  w8TAboveJVinmadeown.may
		$a_01_4 = {6f 66 73 61 79 69 6e 67 66 4e 6d 6f 76 65 64 73 65 61 73 } //01 00  ofsayingfNmovedseas
		$a_01_5 = {71 59 49 78 55 42 65 67 69 6e 6e 69 6e 67 6d 68 69 6d 65 61 72 74 68 } //01 00  qYIxUBeginningmhimearth
		$a_01_6 = {2a 69 71 38 30 52 41 43 4a 4b 5a 32 74 6a 72 77 2e 70 64 62 } //00 00  *iq80RACJKZ2tjrw.pdb
	condition:
		any of ($a_*)
 
}