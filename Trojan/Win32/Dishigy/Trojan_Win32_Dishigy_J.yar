
rule Trojan_Win32_Dishigy_J{
	meta:
		description = "Trojan:Win32/Dishigy.J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {69 c3 01 0a 00 00 8b ?? e4 83 ?? ?? 76 ?? e8 ?? ?? ?? ?? 69 ?? 32 f4 01 00 8d ?? ?? ?? ?? ?? ?? 8d 04 } //1
		$a_00_1 = {3c 71 72 63 6a 3d 2f 6f 69 71 58 } //1 <qrcj=/oiqX
		$a_00_2 = {6c 6f 67 69 6e 3d 5b 31 30 30 30 5d 26 70 61 73 73 3d 5b 31 30 30 30 5d 26 70 61 73 73 77 6f 72 64 3d 5b 35 30 5d 26 6c 6f 67 3d 5b 35 30 5d 26 70 61 73 73 77 72 64 3d 5b 35 30 5d 26 75 73 65 72 3d 5b 35 30 5d } //1 login=[1000]&pass=[1000]&password=[50]&log=[50]&passwrd=[50]&user=[50]
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}