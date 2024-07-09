
rule TrojanDropper_Win32_Zegost_Y{
	meta:
		description = "TrojanDropper:Win32/Zegost.Y,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {30 5c 72 6f 73 73 65 63 6f 72 50 6c 61 72 74 6e 65 43 5c 6d 65 74 73 79 53 5c 4e 4f 49 54 50 49 52 43 53 45 44 5c 45 52 41 57 44 52 41 48 } //1 0\rossecorPlartneC\metsyS\NOITPIRCSED\ERAWDRAH
		$a_01_1 = {48 74 74 70 2f 31 2e 31 20 34 30 33 20 46 6f 72 62 69 64 64 65 6e } //1 Http/1.1 403 Forbidden
		$a_01_2 = {8a 1c 11 80 c3 7a 88 1c 11 8b 55 fc 8a 1c 11 80 f3 19 88 1c 11 } //1
		$a_03_3 = {c6 44 24 10 7e 89 44 24 04 89 44 24 08 8d 44 24 00 c6 44 24 11 4d 50 68 ?? ?? ?? ?? 68 02 00 00 80 c6 44 24 1e 48 c6 44 24 1f 7a c6 44 24 20 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}