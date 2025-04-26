
rule Trojan_Win64_ShellcodeRunner_GPAX_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.GPAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 74 72 4d 45 64 75 50 4e 66 4e 2e 28 2a 65 6e 64 70 6f 69 6e 74 4c 69 73 74 29 2e 53 74 61 74 65 54 79 70 65 4e 61 6d 65 } //2 BtrMEduPNfN.(*endpointList).StateTypeName
	condition:
		((#a_01_0  & 1)*2) >=2
 
}