
rule Trojan_Win32_Deyma_MBJZ_MTB{
	meta:
		description = "Trojan:Win32/Deyma.MBJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c3 33 db 33 d8 80 07 90 01 01 33 c6 8b f3 8b c6 8b c0 8b f3 8b db 33 d8 33 c3 33 c6 f6 2f 47 e2 ab 90 00 } //01 00 
		$a_01_1 = {76 64 77 78 66 79 74 68 64 72 6e 72 61 6d 64 70 65 76 77 63 78 71 74 64 67 6c 6b 74 67 } //00 00  vdwxfythdrnramdpevwcxqtdglktg
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Deyma_MBJZ_MTB_2{
	meta:
		description = "Trojan:Win32/Deyma.MBJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {71 76 64 77 78 66 79 74 68 64 72 6e 72 61 6d 64 70 65 76 77 63 78 71 74 64 67 6c 6b 74 67 78 79 } //01 00  qvdwxfythdrnramdpevwcxqtdglktgxy
		$a_01_1 = {74 69 77 6f 79 62 6c 6c 70 61 6e 70 65 63 69 7a 70 6f 64 74 7a 62 64 62 66 6a 79 6f 62 68 6b 71 6e 64 6a 77 6b 61 79 61 68 78 76 6c 66 66 6c 66 61 6b 73 77 68 78 6c 72 6f 68 72 79 62 79 78 6b 6a 7a 6c 79 74 6a 6a 73 6e 66 65 78 66 64 69 66 66 62 78 68 6e 70 } //01 00  tiwoybllpanpecizpodtzbdbfjyobhkqndjwkayahxvlfflfakswhxlrohrybyxkjzlytjjsnfexfdiffbxhnp
		$a_01_2 = {69 66 65 72 70 62 6a 67 79 75 6a 71 62 6c 74 63 74 68 6f 71 71 77 66 6d 66 6e 77 73 72 75 6c 75 73 6e 6e 66 75 63 76 6c 72 6b 65 7a 6d 78 78 6b 71 77 69 6d 6d 74 78 74 78 6c 63 6c 70 68 6a 6f 6a 6c 73 6f 76 77 6d 75 6a 68 6c 6d 61 79 71 76 68 78 75 66 6b 6d 77 6e } //00 00  iferpbjgyujqbltcthoqqwfmfnwsrulusnnfucvlrkezmxxkqwimmtxtxlclphjojlsovwmujhlmayqvhxufkmwn
	condition:
		any of ($a_*)
 
}