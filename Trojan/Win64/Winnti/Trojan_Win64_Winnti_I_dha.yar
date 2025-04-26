
rule Trojan_Win64_Winnti_I_dha{
	meta:
		description = "Trojan:Win64/Winnti.I!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 61 6e 67 6f 2d 62 61 73 69 63 2d 77 69 6e 33 32 2e 64 6c 6c } //1 pango-basic-win32.dll
		$a_01_1 = {74 61 6e 67 6f 2e 64 6c 6c } //1 tango.dll
		$a_01_2 = {25 73 5c 25 64 25 64 2e 64 61 74 } //1 %s\%d%d.dat
		$a_01_3 = {25 73 5c 73 79 73 70 72 65 70 5c 63 72 79 70 74 62 61 73 65 2e 64 6c 6c } //1 %s\sysprep\cryptbase.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win64_Winnti_I_dha_2{
	meta:
		description = "Trojan:Win64/Winnti.I!dha,SIGNATURE_TYPE_PEHSTR,64 00 64 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 61 6e 67 6f 2d 62 61 73 69 63 2d 77 69 6e 33 32 2e 64 6c 6c } //1 pango-basic-win32.dll
		$a_01_1 = {74 61 6e 67 6f 2e 64 6c 6c } //1 tango.dll
		$a_01_2 = {25 73 5c 25 64 25 64 2e 64 61 74 } //1 %s\%d%d.dat
		$a_01_3 = {25 73 5c 73 79 73 70 72 65 70 5c 63 72 79 70 74 62 61 73 65 2e 64 6c 6c } //1 %s\sysprep\cryptbase.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=100
 
}