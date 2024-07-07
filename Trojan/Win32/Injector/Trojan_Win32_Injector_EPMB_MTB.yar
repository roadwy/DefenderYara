
rule Trojan_Win32_Injector_EPMB_MTB{
	meta:
		description = "Trojan:Win32/Injector.EPMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {43 65 73 61 72 75 6d 65 6e 75 76 63 65 72 } //Cesarumenuvcer  1
		$a_80_1 = {65 77 72 64 73 63 65 73 77 61 } //ewrdsceswa  1
		$a_80_2 = {75 6d 65 72 64 78 6e 73 63 73 65 71 77 } //umerdxnscseqw  1
		$a_80_3 = {4e 75 6d 6d 64 61 64 6b 6f 61 77 64 } //Nummdadkoawd  1
		$a_80_4 = {65 63 32 6e 64 6d 34 73 65 61 77 37 64 6d 63 } //ec2ndm4seaw7dmc  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}