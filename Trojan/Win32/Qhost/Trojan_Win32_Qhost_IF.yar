
rule Trojan_Win32_Qhost_IF{
	meta:
		description = "Trojan:Win32/Qhost.IF,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 75 73 65 72 73 2e 74 78 74 } //03 00  c:\users.txt
		$a_01_1 = {6b 6c 65 6e 69 72 6b 65 6e 20 62 65 6b 6c 65 79 69 6e 69 7a 2e 2e 2e } //03 00  klenirken bekleyiniz...
		$a_01_2 = {73 69 6b 65 73 69 6b 65 6f 6c 6d } //03 00  sikesikeolm
		$a_01_3 = {74 66 65 6e 20 66 6c 61 73 68 20 70 6c 61 79 65 72 20 79 } //00 00  tfen flash player y
		$a_00_4 = {5d 04 00 00 17 0d } //03 80 
	condition:
		any of ($a_*)
 
}