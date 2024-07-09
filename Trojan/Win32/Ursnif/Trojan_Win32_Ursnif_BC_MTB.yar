
rule Trojan_Win32_Ursnif_BC_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {42 6f 72 6e } //1 Born
		$a_81_1 = {46 69 74 73 65 63 6f 6e 64 } //1 Fitsecond
		$a_81_2 = {50 61 73 74 70 75 74 } //1 Pastput
		$a_02_3 = {c1 e0 06 33 c9 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 13 d1 [0-11] 83 c0 62 2b 05 ?? ?? ?? ?? 33 c9 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}
rule Trojan_Win32_Ursnif_BC_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {2b d0 0f b7 0d ?? ?? ?? ?? 03 d1 0f b7 05 ?? ?? ?? ?? 03 c2 66 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 ?? a1 ?? ?? ?? ?? 89 82 } //1
		$a_02_1 = {2b ca 88 0d ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 0f b6 0d 90 08 20 00 0f b7 05 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 03 c1 2b 05 ?? ?? ?? ?? a2 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Ursnif_BC_MTB_3{
	meta:
		description = "Trojan:Win32/Ursnif.BC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2e 65 78 65 00 40 47 65 74 46 69 72 73 74 56 69 63 65 43 69 74 79 40 34 } //1 攮數䀀敇䙴物瑳楖散楃祴㑀
	condition:
		((#a_01_0  & 1)*1) >=1
 
}