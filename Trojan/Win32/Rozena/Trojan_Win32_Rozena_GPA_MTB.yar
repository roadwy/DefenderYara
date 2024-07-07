
rule Trojan_Win32_Rozena_GPA_MTB{
	meta:
		description = "Trojan:Win32/Rozena.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 f1 56 88 8c 05 d4 fd ff ff 40 3d 24 02 00 00 72 e8 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}