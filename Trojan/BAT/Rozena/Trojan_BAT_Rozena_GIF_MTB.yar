
rule Trojan_BAT_Rozena_GIF_MTB{
	meta:
		description = "Trojan:BAT/Rozena.GIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {64 43 41 6b 64 6d 46 79 58 32 4e 76 5a 47 55 75 51 32 39 31 62 6e 51 37 49 43 52 34 4b 79 73 70 49 48 73 } //dCAkdmFyX2NvZGUuQ291bnQ7ICR4KyspIHs  1
		$a_80_1 = {39 49 43 52 32 59 58 4a 66 59 32 39 6b 5a 56 73 6b 65 46 30 67 4c 57 4a 34 62 33 49 67 4e 6a 6b 67 4c 57 4a 34 62 33 49 67 4d } //9ICR2YXJfY29kZVskeF0gLWJ4b3IgNjkgLWJ4b3IgM  1
		$a_80_2 = {73 70 7a 7a 63 69 66 79 20 74 68 7a 7a 20 2d 7a 7a 78 74 72 61 63 74 } //spzzcify thzz -zzxtract  1
		$a_80_3 = {2d 77 68 61 74 74 } //-whatt  1
		$a_80_4 = {2d 65 78 74 64 75 6d 6d 74 } //-extdummt  1
		$a_80_5 = {6f 75 74 2d 73 74 72 69 6e 67 } //out-string  1
		$a_80_6 = {50 6f 77 65 72 53 68 65 6c 6c } //PowerShell  1
		$a_80_7 = {7a 7a 78 74 72 61 63 74 69 6f 6e } //zzxtraction  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}