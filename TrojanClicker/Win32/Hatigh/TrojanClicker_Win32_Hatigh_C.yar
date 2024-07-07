
rule TrojanClicker_Win32_Hatigh_C{
	meta:
		description = "TrojanClicker:Win32/Hatigh.C,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_03_0 = {81 38 68 69 64 64 75 90 01 01 90 03 0e 17 68 90 01 04 68 90 01 04 e8 90 01 02 00 00 ff 75 f0 e8 90 01 02 00 00 c7 45 ec 00 00 00 00 eb 90 01 01 ff 75 f0 90 00 } //10
		$a_01_1 = {eb 05 22 25 73 22 00 68 } //1
		$a_00_2 = {76 61 6c 75 65 3d 6e 6f 5f 73 70 79 77 61 72 65 } //1 value=no_spyware
		$a_00_3 = {2f 6b 77 5f 69 6d 67 2f 69 6d 67 5f 67 65 6e 2e 70 68 70 } //1 /kw_img/img_gen.php
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=11
 
}