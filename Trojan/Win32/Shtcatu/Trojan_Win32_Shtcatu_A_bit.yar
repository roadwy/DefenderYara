
rule Trojan_Win32_Shtcatu_A_bit{
	meta:
		description = "Trojan:Win32/Shtcatu.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 68 75 74 64 6f 77 6e 20 2d 72 20 2d 66 20 2d 74 20 30 30 } //1 shutdown -r -f -t 00
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_03_2 = {63 3a 5c 74 65 6d 70 5c 90 02 0f 2e 65 78 65 90 00 } //1
		$a_01_3 = {63 61 70 74 75 72 61 2e 62 6d 70 } //1 captura.bmp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}