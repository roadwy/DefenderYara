
rule Trojan_Win64_RutzPatchAms_A_MTB{
	meta:
		description = "Trojan:Win64/RutzPatchAms.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {41 6d 73 69 53 63 61 6e 42 75 66 66 65 72 } //1 AmsiScanBuffer
		$a_01_1 = {67 69 74 68 75 62 2e 63 6f 6d 2f 63 32 70 61 69 6e } //1 github.com/c2pain
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}