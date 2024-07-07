
rule Trojan_Win32_Windigo_MB_MTB{
	meta:
		description = "Trojan:Win32/Windigo.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 07 00 00 "
		
	strings :
		$a_01_0 = {47 34 70 6a 4c 57 4c 37 70 33 39 6f 53 71 72 43 6f } //5 G4pjLWL7p39oSqrCo
		$a_01_1 = {4f 2d 46 55 2f 47 6e 53 32 48 48 4f 55 5f 79 77 57 56 39 58 67 45 36 5f 28 75 35 32 5f } //5 O-FU/GnS2HHOU_ywWV9XgE6_(u52_
		$a_01_2 = {67 6a 62 59 61 77 64 54 6a 49 4f 67 32 43 53 75 2f 68 36 66 61 6b 4a 45 68 4a 67 31 4b 6e 63 63 } //5 gjbYawdTjIOg2CSu/h6fakJEhJg1Kncc
		$a_01_3 = {62 59 61 77 64 54 6a 49 4f 67 32 43 53 75 2f 68 36 66 61 6b 4a 45 68 4a 67 31 4b 6e 63 63 9b } //5
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_5 = {55 50 58 30 } //1 UPX0
		$a_01_6 = {55 50 58 31 } //1 UPX1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=23
 
}