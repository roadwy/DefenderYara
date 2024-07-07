
rule Trojan_Win32_Mespam_F{
	meta:
		description = "Trojan:Win32/Mespam.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f be 50 01 83 fa 55 0f 85 90 01 04 8b 45 90 01 01 0f be 50 03 83 fa 3a 0f 85 90 01 04 8b 75 90 01 01 6a 04 90 00 } //1
		$a_01_1 = {70 66 78 7a 6d 74 00 } //1
		$a_01_2 = {7a 70 75 72 73 65 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}