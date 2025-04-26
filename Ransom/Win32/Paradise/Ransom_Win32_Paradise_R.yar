
rule Ransom_Win32_Paradise_R{
	meta:
		description = "Ransom:Win32/Paradise.R,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 6f 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 70 6c 65 61 73 65 20 63 6f 6e 74 61 63 74 20 75 73 20 62 79 20 6d 61 69 6c } //1 To decrypt your files, please contact us by mail
		$a_01_1 = {2f 63 20 76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 /c vssadmin delete shadows /all /quiet
		$a_01_2 = {70 61 72 61 64 69 73 65 5f 6b 65 79 5f 70 75 62 2e 62 69 6e } //1 paradise_key_pub.bin
		$a_01_3 = {77 69 74 68 20 72 65 73 70 65 63 74 20 52 61 6e 73 6f 6d 77 61 72 65 20 50 61 72 61 64 69 73 65 20 54 65 61 6d } //1 with respect Ransomware Paradise Team
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}