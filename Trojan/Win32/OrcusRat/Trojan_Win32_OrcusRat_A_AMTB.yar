
rule Trojan_Win32_OrcusRat_A_AMTB{
	meta:
		description = "Trojan:Win32/OrcusRat.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {57 61 76 65 20 4b 65 79 20 4c 6f 61 64 65 72 } //Wave Key Loader  1
		$a_80_1 = {48 61 76 65 20 79 6f 75 20 64 69 73 61 62 6c 65 64 20 54 61 6d 70 65 72 20 50 72 6f 74 65 63 74 69 6f 6e } //Have you disabled Tamper Protection  1
		$a_80_2 = {47 65 6e 65 72 61 74 69 6e 67 20 66 61 6b 65 20 6b 65 79 20 68 61 73 68 } //Generating fake key hash  1
		$a_80_3 = {49 6e 69 74 69 61 6c 69 7a 69 6e 67 20 62 79 70 61 73 73 20 73 65 71 75 65 6e 63 65 } //Initializing bypass sequence  1
		$a_80_4 = {64 69 73 63 6f 72 64 2e 67 67 2f 77 61 74 65 72 } //discord.gg/water  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}