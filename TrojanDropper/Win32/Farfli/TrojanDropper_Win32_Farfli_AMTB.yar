
rule TrojanDropper_Win32_Farfli_AMTB{
	meta:
		description = "TrojanDropper:Win32/Farfli!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {44 21 45 26 46 28 47 2a 48 2c 49 2d 4b 2e 70 35 72 37 73 39 74 3b 75 3d 76 3e 77 3f 78 40 79 41 7a 42 7b 44 7c 46 7d 48 7e 4a } //D!E&F(G*H,I-K.p5r7s9t;u=v>w?x@yAzB{D|F}H~J  1
		$a_80_1 = {67 65 74 5f 56 69 72 74 75 61 6c 41 64 64 72 65 73 73 } //get_VirtualAddress  1
		$a_80_2 = {67 65 74 5f 54 61 72 67 65 74 4f 66 66 73 65 74 } //get_TargetOffset  1
		$a_80_3 = {67 65 74 5f 46 75 6c 6c 4e 61 6d 65 } //get_FullName  1
		$a_80_4 = {46 69 6c 65 49 6e 66 6f } //FileInfo  1
		$a_80_5 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //VirtualProtect  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}