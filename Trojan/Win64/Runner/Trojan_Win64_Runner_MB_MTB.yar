
rule Trojan_Win64_Runner_MB_MTB{
	meta:
		description = "Trojan:Win64/Runner.MB!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 33 45 78 74 2f 48 6f 6f 6b 61 } //1 D3Ext/Hooka
		$a_01_1 = {53 68 65 6c 6c 63 6f 64 65 20 73 68 6f 75 6c 64 20 68 61 76 65 20 62 65 65 6e 20 65 78 65 63 75 74 65 64 21 } //1 Shellcode should have been executed!
		$a_01_2 = {62 69 6e 6a 65 63 74 } //1 binject
		$a_01_3 = {53 75 70 70 61 44 75 70 70 61 } //1 SuppaDuppa
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}