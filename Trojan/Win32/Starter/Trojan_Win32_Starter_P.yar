
rule Trojan_Win32_Starter_P{
	meta:
		description = "Trojan:Win32/Starter.P,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {81 39 52 65 67 4f 75 ?? 8d 41 04 81 38 70 65 6e 4b } //1
		$a_03_1 = {81 39 45 78 69 74 75 ?? 8d 41 04 81 38 50 72 6f 63 } //1
		$a_01_2 = {66 c7 85 00 fd ff ff 73 00 66 c7 85 02 fd ff ff 68 00 66 c7 85 04 fd ff ff 65 00 } //1
		$a_03_3 = {32 84 95 00 [0-01] ff ff 8b 95 4c ff ff ff 88 04 32 46 ff 8d 3c ff ff ff 75 } //1
		$a_01_4 = {c6 85 2f ff ff ff 61 c6 85 30 ff ff ff 64 c6 85 31 ff ff ff 76 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule Trojan_Win32_Starter_P_2{
	meta:
		description = "Trojan:Win32/Starter.P,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {81 39 52 65 67 4f 75 ?? 8d 41 04 81 38 70 65 6e 4b } //1
		$a_03_1 = {81 39 45 78 69 74 75 ?? 8d 41 04 81 38 50 72 6f 63 } //1
		$a_01_2 = {66 c7 85 00 fd ff ff 73 00 66 c7 85 02 fd ff ff 68 00 66 c7 85 04 fd ff ff 65 00 } //1
		$a_03_3 = {32 84 95 00 [0-01] ff ff 8b 95 4c ff ff ff 88 04 32 46 ff 8d 3c ff ff ff 75 } //1
		$a_01_4 = {c6 85 2f ff ff ff 61 c6 85 30 ff ff ff 64 c6 85 31 ff ff ff 76 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}