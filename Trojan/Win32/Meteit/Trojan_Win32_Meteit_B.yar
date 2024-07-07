
rule Trojan_Win32_Meteit_B{
	meta:
		description = "Trojan:Win32/Meteit.B,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 61 74 72 31 63 6b 6a 61 6e 65 2e 63 6f 6d 2f 72 75 6e 6b 2f 73 2e 70 68 70 } //1 patr1ckjane.com/runk/s.php
		$a_01_1 = {77 68 6f 69 73 6d 69 73 74 65 72 67 72 65 65 6e 2e 63 6f 6d 2f 72 75 6e 6b 2f 63 2e 70 68 70 } //1 whoismistergreen.com/runk/c.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}