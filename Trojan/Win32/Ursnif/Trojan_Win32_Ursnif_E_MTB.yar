
rule Trojan_Win32_Ursnif_E_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b ff c7 05 90 02 30 01 05 90 02 30 8b ff a1 90 02 20 8b 0d 90 02 20 89 08 90 00 } //1
		$a_02_1 = {8b 45 fc 89 45 90 01 01 8b 0d 90 02 20 03 4d 90 01 01 89 0d 90 02 20 8b 55 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Ursnif_E_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {2d 59 11 00 00 90 02 30 81 c2 59 11 00 00 90 02 ff 00 00 90 02 60 31 0d 90 02 ff 89 11 90 00 } //1
		$a_03_1 = {50 6a 2d e8 90 0a ff 00 8b 11 81 ea 90 02 0a 89 10 90 02 ff ba 39 00 00 00 85 d2 75 90 00 } //1
		$a_01_2 = {52 75 50 32 58 62 41 24 53 73 65 33 } //1 RuP2XbA$Sse3
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule Trojan_Win32_Ursnif_E_MTB_3{
	meta:
		description = "Trojan:Win32/Ursnif.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {c6 00 6b c6 40 01 65 c6 40 02 72 c6 40 03 6e c6 40 04 65 c6 40 05 6c c6 40 06 33 } //1
		$a_00_1 = {c7 03 48 65 61 70 66 c7 43 04 43 72 66 c7 43 06 65 61 } //1
		$a_80_2 = {6a 72 72 6d 72 72 79 72 6a 67 79 6e } //jrrmrryrjgyn  1
		$a_80_3 = {72 72 6d 72 72 79 72 6a 67 79 6e } //rrmrryrjgyn  1
		$a_80_4 = {71 77 6c 6c 6a 69 75 70 71 74 } //qwlljiupqt  1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}