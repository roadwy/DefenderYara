
rule Trojan_Win64_Midie_GP_MTB{
	meta:
		description = "Trojan:Win64/Midie.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {64 62 64 6a 55 4b 4c 58 78 5a 7a 79 66 } //dbdjUKLXxZzyf  1
		$a_80_1 = {4b 59 67 57 47 76 4c 64 57 6e 4a 4d 63 54 } //KYgWGvLdWnJMcT  1
		$a_80_2 = {78 72 45 41 66 46 72 43 48 62 42 43 45 30 } //xrEAfFrCHbBCE0  1
		$a_80_3 = {45 61 56 4d 6c 54 4b 48 6d 50 50 49 59 4b 58 } //EaVMlTKHmPPIYKX  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}