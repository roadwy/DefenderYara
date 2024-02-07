
rule Trojan_Win32_Porchanspi_B{
	meta:
		description = "Trojan:Win32/Porchanspi.B,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {41 6e 74 69 2d 43 68 69 6c 64 20 50 6f 72 6e 20 53 70 61 6d 20 50 72 6f 74 65 63 74 69 6f 6e 20 28 31 38 20 55 2e 53 2e 43 2e 20 } //02 00  Anti-Child Porn Spam Protection (18 U.S.C. 
		$a_01_1 = {57 72 6f 6e 67 20 63 6f 64 65 21 } //05 00  Wrong code!
		$a_01_2 = {59 6f 75 72 20 49 64 20 23 3a 20 20 4f 75 72 20 73 70 65 63 69 61 6c 20 73 65 72 76 69 63 65 20 65 6d 61 69 6c 3a 20 73 65 63 75 72 69 74 79 31 31 32 32 30 40 67 6d 61 69 6c 2e 63 6f 6d } //00 00  Your Id #:  Our special service email: security11220@gmail.com
		$a_00_3 = {5d 04 00 00 cb d9 02 } //80 5c 
	condition:
		any of ($a_*)
 
}