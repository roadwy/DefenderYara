
rule Trojan_Win64_ExhaustRAT_AB_MTB{
	meta:
		description = "Trojan:Win64/ExhaustRAT.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {45 78 68 61 75 73 74 2d 52 41 54 } //1 Exhaust-RAT
		$a_81_1 = {48 4b 4c 4d 5c 53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 46 6f 6c 64 65 72 5c 73 68 65 6c 6c 5c 73 61 6e 64 62 6f 78 } //1 HKLM\Software\Classes\Folder\shell\sandbox
		$a_81_2 = {47 65 74 43 6f 6d 70 75 74 65 72 4e 61 6d 65 45 78 41 } //1 GetComputerNameExA
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}