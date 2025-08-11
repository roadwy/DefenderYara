
rule Trojan_Win32_Virlock_SL_MTB{
	meta:
		description = "Trojan:Win32/Virlock.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 06 90 32 c2 88 07 90 e9 c5 ff ff ff } //2
		$a_01_1 = {42 46 47 90 49 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}