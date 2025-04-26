
rule Trojan_Win32_Zenpak_MBJG_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.MBJG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 6e 65 6f 68 65 33 31 2e 64 6c 6c 00 49 65 68 68 7a 72 66 4c 69 65 65 72 61 74 69 00 6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}