
rule Trojan_Win32_Smasarch_D{
	meta:
		description = "Trojan:Win32/Smasarch.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {76 65 72 69 66 79 2e 73 6d 73 73 74 61 74 75 73 2e 63 6f 6d } //01 00  verify.smsstatus.com
		$a_00_1 = {73 68 61 72 65 77 61 72 65 2e 70 72 6f 2f 73 75 70 70 6f 72 74 } //01 00  shareware.pro/support
		$a_01_2 = {63 61 70 74 75 72 61 2e 62 6d 70 } //00 00  captura.bmp
	condition:
		any of ($a_*)
 
}