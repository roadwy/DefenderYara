
rule Trojan_Win32_Stealer_CN_MTB{
	meta:
		description = "Trojan:Win32/Stealer.CN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 e9 81 c1 ?? ?? ?? ?? 33 31 89 ef 81 c7 ?? ?? ?? ?? 2b 37 89 eb 81 c3 ?? ?? ?? ?? 31 33 89 e8 } //1
		$a_03_1 = {31 18 89 e8 05 ?? ?? ?? ?? 81 00 ?? ?? ?? ?? 89 ea 81 c2 ?? ?? ?? ?? 8a 0a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}