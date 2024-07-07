
rule DDoS_Win32_Nitol_G{
	meta:
		description = "DDoS:Win32/Nitol.G,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {59 6f 77 21 20 42 61 64 20 68 6f 73 74 20 6c 6f 6f 6b 75 70 2e 00 } //1 潙ⅷ䈠摡栠獯⁴潬歯灵.
		$a_00_1 = {48 6f 73 74 20 6e 61 6d 65 20 69 73 3a 20 25 73 0a 00 } //1
		$a_00_2 = {41 64 64 72 65 73 73 20 25 64 20 3a 20 25 73 0a 00 } //1
		$a_01_3 = {33 d2 8a 11 03 c2 8b c8 25 ff ff 00 00 c1 e9 10 03 c8 8b c1 c1 e8 10 03 c1 f7 d0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}