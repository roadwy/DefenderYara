
rule Trojan_Win32_Zlob_AU{
	meta:
		description = "Trojan:Win32/Zlob.AU,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0d 00 08 00 00 "
		
	strings :
		$a_01_0 = {a0 15 a7 34 87 65 d0 11 92 4a 00 20 af c7 ac 4d 61 16 0c d3 af cd d0 11 8a 3e 00 c0 4f c9 e2 6e a3 01 48 fc a9 2b cf 11 a2 29 00 aa 00 3d 73 52 84 b2 96 b1 b4 ba 1a 10 b6 9c 00 aa 00 34 1d 07 } //10
		$a_03_1 = {81 78 08 94 01 00 00 75 (0b 8b 44 24 14 c7 40 20|07 c7 46 20) 02 00 00 00 } //1
		$a_01_2 = {00 74 73 5c 00 72 20 4f 62 6a 65 63 00 72 20 48 65 6c 70 65 00 72 5c 42 72 6f 77 73 65 00 } //1 琀屳爀传橢捥爀䠠汥数爀䉜潲獷e
		$a_03_3 = {74 73 5c 00 65 72 20 4f 62 6a 65 63 00 [0-03] 73 65 72 20 48 65 6c 70 00 [0-03] 72 65 72 5c 42 72 6f 77 00 } //1
		$a_01_4 = {72 00 65 00 73 00 3a 00 2f 00 2f 00 25 00 73 00 5c 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 30 00 34 00 2e 00 68 00 74 00 6d 00 } //1 res://%s\s%s%s%s04.htm
		$a_01_5 = {25 00 73 00 73 00 3a 00 2f 00 2f 00 25 00 73 00 5c 00 73 00 68 00 64 00 6f 00 25 00 73 00 25 00 73 00 72 00 72 00 25 00 73 00 25 00 73 00 } //1 %ss://%s\shdo%s%srr%s%s
		$a_01_6 = {25 00 73 00 73 00 3a 00 2f 00 2f 00 25 00 73 00 5c 00 73 00 68 00 25 00 73 00 25 00 73 00 72 00 72 00 25 00 73 00 25 00 73 00 } //1 %ss://%s\sh%s%srr%s%s
		$a_01_7 = {67 65 6f 72 67 69 61 20 6d 64 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=13
 
}