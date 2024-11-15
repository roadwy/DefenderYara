
rule Trojan_Win64_RustWorm_DA_MTB{
	meta:
		description = "Trojan:Win64/RustWorm.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 "
		
	strings :
		$a_80_0 = {70 6b 69 6c 6c 61 70 74 2d 67 65 74 72 65 6d 6f 76 65 2d 79 73 79 73 74 65 6d 63 74 6c 6d 61 73 6b } //pkillapt-getremove-ysystemctlmask  10
		$a_80_1 = {44 69 73 61 62 6c 65 64 20 61 6e 64 20 72 65 6d 6f 76 65 64 3a } //Disabled and removed:  1
		$a_80_2 = {72 6f 6f 74 6b 69 74 73 75 72 69 63 61 74 61 } //rootkitsuricata  10
		$a_80_3 = {63 72 6f 77 64 73 74 72 69 6b 65 66 61 6c 63 6f 6e } //crowdstrikefalcon  1
		$a_80_4 = {77 69 70 74 61 62 6c 65 73 66 69 72 65 77 61 6c 6c } //wiptablesfirewall  1
		$a_80_5 = {6d 61 6c 77 61 72 65 62 79 74 65 73 } //malwarebytes  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*10+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=24
 
}