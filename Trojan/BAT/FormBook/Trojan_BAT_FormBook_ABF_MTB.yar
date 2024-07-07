
rule Trojan_BAT_FormBook_ABF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 11 08 91 11 0a 61 13 0b 07 11 07 07 8e 69 5d 91 13 0c 11 0b 11 0c 20 00 01 00 00 58 59 13 0d 07 11 08 11 0d 20 00 01 00 00 5d d2 9c 11 06 17 58 } //2
		$a_01_1 = {50 00 68 00 6f 00 74 00 6f 00 53 00 6f 00 72 00 74 00 65 00 72 00 } //1 PhotoSorter
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_FormBook_ABF_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 04 6f 90 01 01 00 00 0a 9d 6f 90 01 01 00 00 0a 17 fe 02 0a 06 2c 0a 00 04 17 6f 90 01 01 00 00 0a 00 00 04 6f 90 01 01 00 00 0a 1f 20 fe 01 0b 07 2c 0a 00 04 17 6f 90 00 } //1
		$a_03_1 = {16 0d 2b 13 00 02 09 02 09 91 90 01 05 59 d2 9c 00 09 17 58 0d 09 02 8e 69 fe 04 13 04 11 04 2d e1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_BAT_FormBook_ABF_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {47 55 49 5f 53 65 72 76 69 63 65 73 2e 43 61 6e 42 6f 47 69 61 6f 56 69 65 6e 47 55 49 } //1 GUI_Services.CanBoGiaoVienGUI
		$a_01_1 = {47 55 49 5f 53 65 72 76 69 63 65 73 2e 44 61 6e 68 53 61 63 68 47 56 31 4c 6f 70 } //1 GUI_Services.DanhSachGV1Lop
		$a_01_2 = {47 55 49 5f 53 65 72 76 69 63 65 73 2e 44 61 6e 68 53 61 63 68 48 6f 63 53 69 6e 68 } //1 GUI_Services.DanhSachHocSinh
		$a_01_3 = {47 55 49 5f 53 65 72 76 69 63 65 73 2e 50 68 61 6e 43 6f 6e 67 47 69 61 6e 67 44 61 79 47 55 49 } //1 GUI_Services.PhanCongGiangDayGUI
		$a_01_4 = {47 55 49 5f 53 65 72 76 69 63 65 73 2e 51 75 61 6e 4c 79 48 6f 53 6f 48 6f 63 53 69 6e 68 } //1 GUI_Services.QuanLyHoSoHocSinh
		$a_01_5 = {47 55 49 5f 53 65 72 76 69 63 65 73 2e 51 75 61 6e 4c 79 4c 6f 70 47 55 49 } //1 GUI_Services.QuanLyLopGUI
		$a_01_6 = {47 55 49 5f 53 65 72 76 69 63 65 73 2e 51 75 61 6e 4c 79 4d 6f 6e 48 6f 63 47 55 49 } //1 GUI_Services.QuanLyMonHocGUI
		$a_01_7 = {47 55 49 5f 53 65 72 76 69 63 65 73 2e 54 68 6f 6e 67 54 69 6e 47 55 49 } //1 GUI_Services.ThongTinGUI
		$a_01_8 = {48 6f 53 6f 48 6f 63 53 69 6e 68 44 54 4c } //1 HoSoHocSinhDTL
		$a_01_9 = {50 68 61 6e 43 6f 6e 67 47 69 61 6e 67 44 61 79 44 54 4c } //1 PhanCongGiangDayDTL
		$a_01_10 = {48 6f 53 6f 48 6f 63 53 69 6e 68 42 55 53 } //1 HoSoHocSinhBUS
		$a_01_11 = {34 30 64 62 64 36 30 33 2d 35 37 35 61 2d 34 33 37 30 2d 62 37 34 35 2d 32 38 34 66 65 66 37 65 31 65 35 31 } //1 40dbd603-575a-4370-b745-284fef7e1e51
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}