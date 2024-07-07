
rule Trojan_Win32_Vareids_A{
	meta:
		description = "Trojan:Win32/Vareids.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 89 50 02 c7 40 04 7f 00 00 01 } //2
		$a_01_1 = {6d 73 76 70 78 38 36 2e 61 71 6d 67 75 } //1 msvpx86.aqmgu
		$a_01_2 = {6d 73 76 6b 78 38 36 2e 61 71 6d 67 75 } //1 msvkx86.aqmgu
		$a_01_3 = {48 41 52 44 56 41 52 45 5f 49 44 25 } //1 HARDVARE_ID%
		$a_01_4 = {53 45 54 54 49 4e 47 53 5f 41 44 4c 45 52 25 } //1 SETTINGS_ADLER%
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}