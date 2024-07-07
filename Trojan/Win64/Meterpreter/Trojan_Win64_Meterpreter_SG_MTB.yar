
rule Trojan_Win64_Meterpreter_SG_MTB{
	meta:
		description = "Trojan:Win64/Meterpreter.SG!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 75 64 65 6d 79 62 61 72 7a 2e 70 64 62 } //2 \udemybarz.pdb
		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_2 = {53 68 65 6c 6c 63 6f 64 65 } //1 Shellcode
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}