
rule Trojan_Win32_Delf_DZ{
	meta:
		description = "Trojan:Win32/Delf.DZ,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 75 6e 69 76 65 72 73 61 6c 31 30 31 2e 63 6f 6d 2f 75 70 64 } //1 http://www.universal101.com/upd
		$a_00_1 = {78 3d 30 2f 65 64 3d 30 2f 65 78 3d 31 } //1 x=0/ed=0/ex=1
		$a_00_2 = {68 74 74 70 3a 2f 2f 61 6b 6c 69 63 6b 2e 69 6e 66 6f 2f 64 2e 70 68 70 3f 64 61 74 65 3d } //2 http://aklick.info/d.php?date=
		$a_03_3 = {52 50 8d 46 48 50 e8 90 01 02 ff ff 83 f8 ff 0f 84 08 01 00 00 89 06 66 81 7e 04 b3 d7 0f 85 c3 00 00 00 66 ff 4e 04 6a 00 ff 36 e8 90 01 02 ff ff 40 90 00 } //10
		$a_02_4 = {2a 72 2a 2e 90 01 01 70 90 01 01 68 90 01 01 70 90 01 01 3f 90 01 01 75 90 01 01 72 90 01 01 6c 90 01 01 3d 90 00 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_03_3  & 1)*10+(#a_02_4  & 1)*2) >=12
 
}