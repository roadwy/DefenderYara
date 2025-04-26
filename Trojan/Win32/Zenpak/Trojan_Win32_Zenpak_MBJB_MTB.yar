
rule Trojan_Win32_Zenpak_MBJB_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.MBJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {67 67 70 74 65 66 39 36 2e 64 6c 6c 00 54 70 6f 6e 66 4b 68 65 65 6d 00 6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 } //1
		$a_01_1 = {66 32 69 7a 6a 4c 45 4e 2e 44 4c 4c 00 73 65 4c 46 2e 45 78 45 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}