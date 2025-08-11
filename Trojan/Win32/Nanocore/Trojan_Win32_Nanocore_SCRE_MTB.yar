
rule Trojan_Win32_Nanocore_SCRE_MTB{
	meta:
		description = "Trojan:Win32/Nanocore.SCRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_81_0 = {76 6f 6b 73 6b 72 74 65 64 69 72 69 67 65 6e 74 75 64 67 72 61 76 6e 69 6e 67 65 72 63 } //2 vokskrtedirigentudgravningerc
		$a_81_1 = {63 72 6f 73 73 66 6c 6f 77 65 72 70 6f 73 69 74 69 6f 6e 73 73 79 73 74 65 6d 73 73 69 } //2 crossflowerpositionssystemssi
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}