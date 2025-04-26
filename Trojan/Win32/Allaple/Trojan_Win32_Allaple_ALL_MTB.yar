
rule Trojan_Win32_Allaple_ALL_MTB{
	meta:
		description = "Trojan:Win32/Allaple.ALL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 3e 02 00 00 b8 ?? ?? ?? ?? 50 ba ce 47 6c a0 e8 ?? ?? ?? ?? eb 09 31 10 83 c0 04 49 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}