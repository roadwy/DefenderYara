
rule Trojan_Win64_CobaltStrike_NWOE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.NWOE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 ff c9 41 8b 34 88 48 01 d6 4d 31 c9 48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 } //1
		$a_81_1 = {4e 74 41 6c 6c 6f 63 61 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //1 NtAllocateVirtualMemory
		$a_81_2 = {53 79 73 74 65 6d 55 70 64 61 74 65 } //1 SystemUpdate
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}