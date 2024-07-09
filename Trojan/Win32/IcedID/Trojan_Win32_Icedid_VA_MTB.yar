
rule Trojan_Win32_Icedid_VA_MTB{
	meta:
		description = "Trojan:Win32/Icedid.VA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {51 6a 40 68 ?? ?? ?? ?? 51 6a 00 ff 93 [0-04] 59 5e 89 83 [0-04] 89 c7 f3 a4 8b b3 [0-04] 8d bb [0-04] 29 f7 01 f8 ff e0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}