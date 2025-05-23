
rule Trojan_Win32_ClickFix_DW_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DW!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,42 00 42 00 10 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //10 mshta
		$a_00_1 = {68 00 74 00 74 00 70 00 } //1 http
		$a_00_2 = {76 00 65 00 72 00 69 00 66 00 } //5 verif
		$a_00_3 = {5c 00 31 00 } //5 \1
		$a_00_4 = {33 04 65 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04 } //50 гeСАРТСНА
		$a_00_5 = {33 04 21 04 10 04 20 04 22 04 21 04 1d 04 10 04 } //50 гСАРТСНА
		$a_00_6 = {33 04 65 00 20 00 21 04 10 04 20 04 22 04 21 04 1d 04 10 04 } //50 гe САРТСНА
		$a_00_7 = {43 00 6c 00 bf 03 75 00 64 00 66 00 6c 00 61 00 72 00 65 00 } //50
		$a_02_8 = {48 00 75 00 6d 00 30 04 6e 00 [0-1e] 21 04 41 00 50 00 54 00 43 00 48 00 41 00 } //50
		$a_00_9 = {21 04 10 04 20 04 22 04 21 04 1d 04 10 04 } //50 САРТСНА
		$a_00_10 = {99 03 20 00 61 00 6d 00 20 00 6e 00 bf 03 74 00 } //50
		$a_00_11 = {52 00 bf 03 62 00 bf 03 74 00 } //50
		$a_00_12 = {60 21 51 02 6d 00 78 05 85 05 74 00 } //50
		$a_00_13 = {7e 02 85 05 62 00 85 05 74 00 } //50
		$a_00_14 = {f9 03 91 03 a1 03 a4 03 43 00 48 00 41 00 } //50
		$a_00_15 = {72 00 0b 20 6f 00 62 00 6f 00 0d 20 74 00 } //50
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5+(#a_00_4  & 1)*50+(#a_00_5  & 1)*50+(#a_00_6  & 1)*50+(#a_00_7  & 1)*50+(#a_02_8  & 1)*50+(#a_00_9  & 1)*50+(#a_00_10  & 1)*50+(#a_00_11  & 1)*50+(#a_00_12  & 1)*50+(#a_00_13  & 1)*50+(#a_00_14  & 1)*50+(#a_00_15  & 1)*50) >=66
 
}