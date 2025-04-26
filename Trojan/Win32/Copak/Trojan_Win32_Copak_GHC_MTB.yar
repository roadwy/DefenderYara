
rule Trojan_Win32_Copak_GHC_MTB{
	meta:
		description = "Trojan:Win32/Copak.GHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 16 81 c6 ?? ?? ?? ?? 01 c9 39 de 75 ed } //10
		$a_03_1 = {31 19 81 ef ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 4e 81 c6 ?? ?? ?? ?? 39 c1 75 e2 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}