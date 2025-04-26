
rule Trojan_Win64_Agent_NME_MTB{
	meta:
		description = "Trojan:Win64/Agent.NME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 8b c3 8b ca [0-0a] 80 30 20 48 ff c0 48 ff c9 75 } //1
		$a_01_1 = {4c 6f 63 6b 44 6f 77 6e 50 72 6f 74 65 63 74 50 72 6f 63 65 73 73 42 79 49 64 } //1 LockDownProtectProcessById
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}