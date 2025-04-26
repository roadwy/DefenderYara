
rule Trojan_Win32_Emotet_SM_MSR{
	meta:
		description = "Trojan:Win32/Emotet.SM!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {7a 73 44 46 63 63 4b 4c 4d 4e 76 63 66 44 78 72 } //1 zsDFccKLMNvcfDxr
		$a_01_1 = {6d 6f 6e 65 79 } //1 money
		$a_01_2 = {70 6c 65 61 73 65 20 65 6e 74 65 72 20 79 6f 75 72 20 6e 61 6d 65 } //1 please enter your name
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}