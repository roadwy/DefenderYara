
rule Trojan_Win32_Lopelmoc_A{
	meta:
		description = "Trojan:Win32/Lopelmoc.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {83 f9 7e 7d 25 0f be 55 cf 83 fa 4f 7d 0c 0f be 45 cf 83 c0 2f } //1
		$a_03_1 = {68 58 03 00 00 e8 ?? ?? ?? ?? 83 c4 04 89 45 fc 83 7d fc 00 0f 84 ?? ?? 00 00 6a ff 8b 45 08 50 68 07 01 00 00 } //1
		$a_01_2 = {55 50 44 41 54 45 20 70 72 6f 70 65 72 74 69 65 73 20 53 45 54 20 69 64 3d 3f } //1 UPDATE properties SET id=?
		$a_01_3 = {68 61 6e 64 6c 65 72 2e 70 68 70 } //1 handler.php
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}