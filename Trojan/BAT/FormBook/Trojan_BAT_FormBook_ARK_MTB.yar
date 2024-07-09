
rule Trojan_BAT_FormBook_ARK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ARK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {14 14 17 8d 16 00 00 01 25 16 07 a2 6f ?? ?? ?? 0a 75 1d 00 00 01 0c 08 6f ?? ?? ?? 0a 16 9a 6f ?? ?? ?? 0a 18 9a 0d 09 16 8c 58 00 00 01 02 7b 0e 00 00 04 13 04 11 04 6f } //2
		$a_01_1 = {51 00 75 00 61 00 6e 00 4c 00 69 00 54 00 68 00 75 00 56 00 69 00 65 00 6e 00 } //1 QuanLiThuVien
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}