
rule Trojan_Win32_Copak_GPAK_MTB{
	meta:
		description = "Trojan:Win32/Copak.GPAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 e0 ea 40 00 [0-20] 31 [0-30] 81 ?? ff 00 00 00 [0-20] f4 01 00 00 75 05 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}