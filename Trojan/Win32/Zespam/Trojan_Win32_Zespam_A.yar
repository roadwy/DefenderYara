
rule Trojan_Win32_Zespam_A{
	meta:
		description = "Trojan:Win32/Zespam.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 61 64 64 5f 61 74 74 61 63 68 5f 75 72 6c 00 } //1 愀摤慟瑴捡彨牵l
		$a_03_1 = {66 8b 11 66 89 55 90 01 01 0f b7 45 90 01 01 50 e8 90 01 04 83 c4 04 0f b7 c8 33 4d 90 01 01 81 e1 ff 00 00 00 8b 55 90 01 01 c1 ea 08 33 14 8d 90 01 04 89 55 90 01 01 8b 45 90 01 01 83 c0 02 89 45 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}