
rule Trojan_Win32_BlackMoon_DW_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {30 78 58 23 ea 5b 23 93 b7 5e 1a 55 15 b1 57 f0 b8 89 4d 78 64 a8 36 51 2d de be af 0b 14 e8 51 } //2
		$a_01_1 = {d1 02 a8 4b 2f 38 08 92 33 77 e1 67 04 fb eb } //2
		$a_01_2 = {43 3a 5c 65 7a 64 75 6e 2e 69 6e 69 } //1 C:\ezdun.ini
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}