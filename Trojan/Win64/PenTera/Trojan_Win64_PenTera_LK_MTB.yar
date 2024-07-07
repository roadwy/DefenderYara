
rule Trojan_Win64_PenTera_LK_MTB{
	meta:
		description = "Trojan:Win64/PenTera.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {31 30 53 65 6c 66 44 65 6c 42 61 74 } //1 10SelfDelBat
		$a_01_1 = {31 31 42 61 73 65 50 61 79 6c 6f 61 64 } //1 11BasePayload
		$a_01_2 = {31 36 53 68 65 6c 6c 63 6f 64 65 50 61 79 6c 6f 61 64 } //1 16ShellcodePayload
		$a_01_3 = {52 65 6d 6f 74 65 52 75 6e 6e 65 72 } //1 RemoteRunner
		$a_01_4 = {39 50 45 50 61 79 6c 6f 61 64 } //1 9PEPayload
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}