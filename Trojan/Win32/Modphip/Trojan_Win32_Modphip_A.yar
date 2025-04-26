
rule Trojan_Win32_Modphip_A{
	meta:
		description = "Trojan:Win32/Modphip.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {76 69 73 75 61 6c 73 74 75 64 69 6f 73 72 63 33 6b 33 00 } //1
		$a_01_1 = {69 64 2e 70 68 70 3f 72 61 6e 64 6f 6d 3d 00 } //1
		$a_01_2 = {73 68 75 74 64 6f 77 6e 20 2d 72 20 2d 74 20 30 00 } //1
		$a_01_3 = {75 70 64 61 74 65 2e 70 68 70 3f 6f 73 3d } //1 update.php?os=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}