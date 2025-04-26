
rule Trojan_Win32_Farfli_DAZ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.DAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 0c c7 45 a8 61 6d 20 46 c7 45 ac 69 6c 65 73 c7 45 b0 20 28 78 38 c7 45 b4 36 29 5c 4d 66 c7 45 b8 69 63 88 5d ba c7 45 bb 6f 73 6f 66 } //1
		$a_03_1 = {50 c7 84 24 ?? ?? 00 00 43 3a 5c 50 c7 84 24 ?? ?? 00 00 72 6f 67 72 c7 84 24 ?? ?? 00 00 61 6d 20 46 c7 84 24 ?? ?? 00 00 69 6c 65 73 c7 84 24 ?? ?? 00 00 20 28 78 38 c7 84 24 ?? ?? 00 00 36 29 5c 4d c7 84 24 ?? ?? 00 00 69 63 72 6f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}