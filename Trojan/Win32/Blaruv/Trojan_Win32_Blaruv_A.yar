
rule Trojan_Win32_Blaruv_A{
	meta:
		description = "Trojan:Win32/Blaruv.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 61 70 70 64 61 74 61 25 5c 6e 69 67 68 74 75 70 64 61 74 65 5c } //1 %appdata%\nightupdate\
		$a_01_1 = {2f 67 61 74 65 2e 70 68 70 3f 63 6d 64 3d 75 72 6c 73 } //1 /gate.php?cmd=urls
		$a_01_2 = {2f 67 61 74 65 2e 70 68 70 3f 72 65 67 3d } //1 /gate.php?reg=
		$a_01_3 = {62 6c 61 63 6b 72 65 76 } //1 blackrev
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}