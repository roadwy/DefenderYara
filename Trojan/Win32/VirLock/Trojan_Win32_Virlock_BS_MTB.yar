
rule Trojan_Win32_Virlock_BS_MTB{
	meta:
		description = "Trojan:Win32/Virlock.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 06 90 32 c2 90 88 07 90 e9 } //4
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}