
rule Trojan_Win64_RedCap_ARA_MTB{
	meta:
		description = "Trojan:Win64/RedCap.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 42 6c 75 65 44 61 73 68 55 70 64 61 74 65 2e 63 6d 64 } //2 1BlueDashUpdate.cmd
		$a_01_1 = {44 65 63 72 79 70 74 46 69 6c 65 41 } //2 DecryptFileA
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}