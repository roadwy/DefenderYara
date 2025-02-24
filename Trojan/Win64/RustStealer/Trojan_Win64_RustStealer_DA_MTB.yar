
rule Trojan_Win64_RustStealer_DA_MTB{
	meta:
		description = "Trojan:Win64/RustStealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 4e 6f 6e 49 6e 74 65 72 61 63 74 69 76 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 43 6f 6d 6d 61 6e 64 } //powershell -NoProfile -NonInteractive -WindowStyle Hidden -Command  10
		$a_80_1 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 72 6f 63 65 73 73 } //Add-MpPreference -ExclusionProcess  10
		$a_80_2 = {67 69 74 68 75 62 2e 63 6f 6d } //github.com  1
		$a_80_3 = {41 50 50 44 41 54 41 } //APPDATA  1
		$a_80_4 = {6d 75 74 65 78 20 70 6f 69 73 6f 6e 65 64 } //mutex poisoned  1
		$a_80_5 = {4f 6e 63 65 20 69 6e 73 74 61 6e 63 65 20 68 61 73 20 70 72 65 76 69 6f 75 73 6c 79 20 62 65 65 6e 20 70 6f 69 73 6f 6e 65 64 } //Once instance has previously been poisoned  1
		$a_80_6 = {76 65 6c 20 63 72 69 61 72 20 6f 20 61 72 71 75 69 76 6f 20 2e 62 61 74 2e } //vel criar o arquivo .bat.  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=25
 
}