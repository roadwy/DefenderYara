
rule Trojan_Win32_Donkaykay_H_dha{
	meta:
		description = "Trojan:Win32/Donkaykay.H!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 20 66 69 6c 65 20 66 61 69 6c 65 64 3a } //1 Open file failed:
		$a_00_1 = {8d 04 45 02 00 00 00 3d 08 02 00 00 73 } //1
		$a_03_2 = {50 6a 40 56 57 ff 15 ?? ?? ?? ?? ff d7 68 00 80 00 00 6a 00 57 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}