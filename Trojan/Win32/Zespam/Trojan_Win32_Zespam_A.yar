
rule Trojan_Win32_Zespam_A{
	meta:
		description = "Trojan:Win32/Zespam.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 61 64 64 5f 61 74 74 61 63 68 5f 75 72 6c 00 } //1 愀摤慟瑴捡彨牵l
		$a_03_1 = {66 8b 11 66 89 55 ?? 0f b7 45 ?? 50 e8 ?? ?? ?? ?? 83 c4 04 0f b7 c8 33 4d ?? 81 e1 ff 00 00 00 8b 55 ?? c1 ea 08 33 14 8d ?? ?? ?? ?? 89 55 ?? 8b 45 ?? 83 c0 02 89 45 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}