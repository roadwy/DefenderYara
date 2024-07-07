
rule Trojan_Win32_Bodime_C{
	meta:
		description = "Trojan:Win32/Bodime.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {74 09 81 7d 08 03 01 00 00 75 1a 68 00 80 00 00 6a 00 56 57 e8 90 01 04 0b d8 81 fe 00 f0 ff 7f 73 07 eb c2 90 00 } //1
		$a_03_1 = {8a 0c 02 80 c1 90 01 01 88 08 40 4e 75 f4 90 00 } //1
		$a_01_2 = {43 41 4f 43 41 4f 53 00 } //1 䅃䍏佁S
		$a_01_3 = {b1 ea d7 bc ca e4 c8 eb b7 a8 c0 a9 d5 b9 b7 fe ce f1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}