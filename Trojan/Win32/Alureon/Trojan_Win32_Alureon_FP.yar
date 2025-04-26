
rule Trojan_Win32_Alureon_FP{
	meta:
		description = "Trojan:Win32/Alureon.FP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {b8 48 48 00 00 8a e8 c7 45 ec 16 00 00 00 } //1
		$a_01_1 = {77 73 72 76 00 00 00 00 70 73 72 76 00 00 00 00 63 73 72 76 } //1
		$a_01_2 = {62 70 73 6c 65 6d 6e 71 20 2d 70 20 6c 61 62 67 73 75 72 77 6b 6b } //1 bpslemnq -p labgsurwkk
		$a_01_3 = {76 65 72 3d 25 73 26 62 69 64 3d 25 73 26 61 69 64 3d 25 73 26 73 69 64 3d 25 73 } //1 ver=%s&bid=%s&aid=%s&sid=%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}