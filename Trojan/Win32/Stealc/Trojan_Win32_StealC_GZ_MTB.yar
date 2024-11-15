
rule Trojan_Win32_StealC_GZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 9c 07 49 9e 00 00 88 1c 06 81 f9 8d 00 00 00 75 06 89 15 ?? ?? ?? ?? 40 3b c1 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}