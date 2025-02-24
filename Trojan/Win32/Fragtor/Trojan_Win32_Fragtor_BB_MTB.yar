
rule Trojan_Win32_Fragtor_BB_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f be 0c 08 8b 95 ?? ff ff ff [0-06] 31 d1 88 ca 8b 8d ?? ff ff ff 88 14 08 8b 85 ?? ff ff ff 83 c0 ?? 89 85 ?? ff ff ff e9 } //2
		$a_01_1 = {66 64 61 73 6b 75 66 68 67 62 6b 73 75 74 68 6c 79 69 6a 68 72 64 } //1 fdaskufhgbksuthlyijhrd
		$a_01_2 = {66 67 68 64 66 74 69 79 68 73 61 62 66 75 44 46 45 52 4b 46 } //1 fghdftiyhsabfuDFERKF
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}