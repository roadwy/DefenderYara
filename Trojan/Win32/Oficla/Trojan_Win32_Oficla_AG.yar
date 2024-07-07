
rule Trojan_Win32_Oficla_AG{
	meta:
		description = "Trojan:Win32/Oficla.AG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {b9 bf a2 1a 50 81 f1 ff a2 1a 50 51 b9 b3 a1 ca 3b 81 f1 b3 b1 ca 3b 51 b9 37 0f 00 00 51 } //1
		$a_01_1 = {64 a1 18 00 00 00 8b 40 34 83 f8 06 74 01 c3 } //1
		$a_00_2 = {66 75 63 6b 20 61 76 } //1 fuck av
		$a_00_3 = {42 00 69 00 74 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 20 00 31 00 30 00 } //1 BitDefender 10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}