
rule Trojan_Win32_Virlock_ARAX_MTB{
	meta:
		description = "Trojan:Win32/Virlock.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 90 e9 } //2
		$a_01_1 = {88 07 42 90 46 47 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_Win32_Virlock_ARAX_MTB_2{
	meta:
		description = "Trojan:Win32/Virlock.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 06 32 c2 e9 ?? 00 00 00 } //2
		$a_01_1 = {88 07 46 90 47 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}