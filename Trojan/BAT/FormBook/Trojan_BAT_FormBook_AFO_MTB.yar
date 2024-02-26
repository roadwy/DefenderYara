
rule Trojan_BAT_FormBook_AFO_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {0d 16 13 0a 2b 11 00 09 11 0a 08 11 0a 94 d2 9c 00 11 0a 17 58 13 0a 11 0a 08 8e 69 fe 04 13 0b 11 0b 2d e2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AFO_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {17 59 9a 0c 08 28 90 01 01 00 00 0a 16 fe 01 13 06 11 06 2d 03 00 2b 2f 00 06 09 6f 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 00 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AFO_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 16 91 13 05 08 17 8d 90 01 03 01 25 16 11 05 9c 6f 90 01 03 0a 09 18 58 0d 09 07 6f 90 01 03 0a fe 04 13 06 11 06 2d c4 90 00 } //01 00 
		$a_01_1 = {51 00 75 00 61 00 6e 00 4c 00 79 00 42 00 61 00 6e 00 48 00 61 00 6e 00 67 00 } //00 00  QuanLyBanHang
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AFO_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 31 00 07 08 09 28 90 01 03 06 28 90 01 03 06 00 28 90 01 03 06 28 90 01 03 06 90 00 } //01 00 
		$a_01_1 = {4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 41 00 72 00 69 00 74 00 68 00 6d 00 65 00 74 00 69 00 63 00 47 00 61 00 6d 00 65 00 } //00 00  NetworkArithmeticGame
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AFO_MTB_5{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {16 0a 2b 19 00 02 06 94 07 fe 02 0c 08 2c 09 00 02 06 94 0b 03 06 54 00 00 06 17 58 0a 06 02 8e 69 fe 04 0d 09 2d } //01 00 
		$a_01_1 = {50 00 61 00 6c 00 65 00 6f 00 6c 00 69 00 74 00 68 00 69 00 63 00 20 00 43 00 6f 00 6f 00 70 00 65 00 72 00 61 00 74 00 69 00 6f 00 6e 00 } //00 00  Paleolithic Cooperation
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AFO_MTB_6{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 13 04 16 13 05 2b 19 11 04 11 05 a3 90 01 01 00 00 01 13 06 09 11 06 6f 90 01 01 00 00 0a 11 05 17 58 13 05 11 05 11 04 8e 69 32 df 90 00 } //01 00 
		$a_03_1 = {0a 16 0b 38 90 01 01 00 00 00 06 07 17 5b 7e 90 01 01 00 00 0a a4 90 01 01 00 00 01 07 17 58 0b 07 02 8e 69 32 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AFO_MTB_7{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {13 04 2b 4e 00 08 11 04 08 8e 69 5d 02 08 11 04 08 8e 69 5d 91 09 11 04 09 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 28 90 01 01 00 00 0a 08 11 04 17 58 08 8e 69 5d 91 90 00 } //01 00 
		$a_01_1 = {53 00 77 00 69 00 74 00 63 00 68 00 62 00 6f 00 61 00 72 00 64 00 53 00 65 00 72 00 76 00 65 00 72 00 } //00 00  SwitchboardServer
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AFO_MTB_8{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 41 59 5f 44 4f 4e 5f 47 49 41 5f 54 48 45 4f 5f 4d 41 5f 48 48 } //01 00  LAY_DON_GIA_THEO_MA_HH
		$a_01_1 = {4c 41 59 5f 53 4f 5f 4c 55 4f 4e 47 5f 54 4f 4e 5f 54 48 45 4f 5f 4d 41 5f 48 48 } //01 00  LAY_SO_LUONG_TON_THEO_MA_HH
		$a_01_2 = {46 72 6d 5f 48 48 5f 43 48 49 5f 54 49 45 54 } //01 00  Frm_HH_CHI_TIET
		$a_01_3 = {51 55 41 4e 5f 53 79 73 74 65 6d 2e 46 72 6d } //01 00  QUAN_System.Frm
		$a_01_4 = {64 63 39 64 33 37 33 66 2d 64 66 61 61 2d 34 33 32 66 2d 39 38 65 63 2d 39 36 35 36 38 32 66 32 64 36 35 66 } //01 00  dc9d373f-dfaa-432f-98ec-965682f2d65f
		$a_01_5 = {32 30 31 36 20 62 79 20 4d 61 6e 4d 61 6e 38 39 } //00 00  2016 by ManMan89
	condition:
		any of ($a_*)
 
}