
rule Trojan_Win32_Shipup_J{
	meta:
		description = "Trojan:Win32/Shipup.J,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {58 50 2d 55 70 64 61 74 65 } //1 XP-Update
		$a_01_1 = {2d 6d 6f 75 73 65 2e 6c 6f 67 } //1 -mouse.log
		$a_01_2 = {6d 73 64 6e 00 00 00 00 5c 2a 2e 2a } //1
		$a_03_3 = {8b 44 24 04 03 c1 8a 10 2a d1 80 f2 ?? 80 ea ?? 41 3b 4c 24 08 88 10 7c e7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}