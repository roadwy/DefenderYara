
rule TrojanDropper_Win32_Noratops_A_dha{
	meta:
		description = "TrojanDropper:Win32/Noratops.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 43 54 49 54 46 5f 66 6f 72 6d 6d 6d 6d } //1 get_CTITF_formmmm
		$a_01_1 = {2e 00 74 00 6d 00 70 00 2c 00 5f 00 64 00 65 00 63 00 } //1 .tmp,_dec
		$a_01_2 = {2f 00 63 00 20 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 20 00 7e 00 24 00 } //1 /c rundll32 ~$
		$a_01_3 = {5c 00 43 00 54 00 49 00 54 00 46 00 20 00 66 00 6f 00 72 00 6d 00 2e 00 70 00 64 00 66 00 } //1 \CTITF form.pdf
		$a_01_4 = {25 50 44 46 2d 31 2e } //1 %PDF-1.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=100
 
}
rule TrojanDropper_Win32_Noratops_A_dha_2{
	meta:
		description = "TrojanDropper:Win32/Noratops.A!dha,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {25 00 73 00 7e 00 24 00 73 00 74 00 25 00 64 00 25 00 64 00 25 00 64 00 2e 00 25 00 73 00 } //1 %s~$st%d%d%d.%s
		$a_01_1 = {2f 00 67 00 65 00 6e 00 65 00 72 00 61 00 6c 00 2e 00 70 00 6e 00 67 00 } //1 /general.png
		$a_01_2 = {22 00 25 00 73 00 22 00 2c 00 5f 00 64 00 65 00 63 00 } //1 "%s",_dec
		$a_01_3 = {2f 00 6e 00 25 00 64 00 2e 00 70 00 6e 00 67 00 } //1 /n%d.png
		$a_01_4 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //1 rundll32.exe
		$a_01_5 = {75 6e 6b 6e 6f 77 6e 20 63 6f 6d 70 72 65 73 73 69 6f 6e 20 6d 65 74 68 6f 64 } //1 unknown compression method
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}