
rule Trojan_Win32_Bandit_GB_MTB{
	meta:
		description = "Trojan:Win32/Bandit.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 c0 01 89 85 90 01 04 8b 8d 90 01 04 3b 0d 90 01 04 73 90 01 01 81 3d 90 01 04 48 07 00 00 75 90 01 01 c7 05 90 01 04 e6 ac 2e 92 8b 95 90 01 04 52 a1 90 01 04 50 e8 90 01 04 83 c4 08 eb 90 00 } //1
		$a_02_1 = {83 c1 01 89 8d 90 01 04 81 bd 90 01 04 1c 86 0d 00 7d 90 01 01 81 bd 90 01 04 7c 87 02 00 75 90 01 01 e8 90 01 04 eb 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}