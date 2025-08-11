
rule Trojan_Win32_Dapato_BAC_MTB{
	meta:
		description = "Trojan:Win32/Dapato.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 47 05 c1 e0 02 01 47 09 8b 57 09 8b 4d f0 89 0a 29 47 09 ff 47 05 8b 45 f4 8b 00 85 c0 74 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}