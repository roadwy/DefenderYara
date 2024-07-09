
rule Trojan_Win64_CrypInject_AFX_MTB{
	meta:
		description = "Trojan:Win64/CrypInject.AFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 44 3b 84 24 ?? ?? ?? ?? 7d 2b 8b 84 24 ?? ?? ?? ?? 48 8b 4c 24 ?? 33 01 89 01 48 8b 44 24 ?? 48 83 c0 04 48 89 44 24 78 8b 44 24 44 83 c0 01 89 44 24 44 eb c8 } //10
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}