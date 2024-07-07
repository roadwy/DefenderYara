
rule Trojan_Win32_Remcos_PR_MTB{
	meta:
		description = "Trojan:Win32/Remcos.PR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {5a b9 e0 d4 00 00 8b 1c 0a 81 f3 90 01 04 89 1c 08 83 e9 90 01 01 7d 90 01 01 ff 90 01 01 e2 90 01 01 99 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}