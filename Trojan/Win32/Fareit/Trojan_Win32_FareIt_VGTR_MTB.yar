
rule Trojan_Win32_FareIt_VGTR_MTB{
	meta:
		description = "Trojan:Win32/FareIt.VGTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {20 5f 41 41 35 4e 85 4d b1 3a 25 78 41 41 d6 be b6 be be 33 3b 1e 4b 41 41 } //1
		$a_81_1 = {49 44 65 73 69 67 6e 65 72 48 6f 6f 6b 40 56 41 } //1 IDesignerHook@VA
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}