
rule Trojan_Win32_StealC_ASL_MTB{
	meta:
		description = "Trojan:Win32/StealC.ASL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 69 00 00 00 66 a3 ?? ?? ?? ?? b9 32 00 00 00 66 89 0d ?? ?? ?? ?? ba 73 00 00 00 66 89 15 ?? ?? ?? ?? b8 33 00 00 00 b9 6c 00 00 00 ba 64 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}