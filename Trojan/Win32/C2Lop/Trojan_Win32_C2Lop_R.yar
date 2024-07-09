
rule Trojan_Win32_C2Lop_R{
	meta:
		description = "Trojan:Win32/C2Lop.R,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {25 66 3a 25 66 [0-04] 74 64 6d 79 2e 63 6f 6d } //1
		$a_00_1 = {64 69 61 6c 69 6e 67 5f 25 73 5f 6e 75 6d 62 65 72 28 25 73 29 3b 6d 6f 64 65 6d 68 75 6e 67 75 70 5b 64 69 61 6c 74 69 6d 65 72 3d 25 64 5d 7c } //1 dialing_%s_number(%s);modemhungup[dialtimer=%d]|
		$a_00_2 = {74 72 69 6e 69 74 79 61 63 71 75 69 73 69 74 69 6f 6e 73 2e 63 6f 6d 00 } //1
		$a_00_3 = {3a 5c 75 6e 73 69 7a 7a 6c 65 2e 62 61 74 00 66 6f 6c 64 65 72 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}