
rule Trojan_Win32_StealC_BAA_MTB{
	meta:
		description = "Trojan:Win32/StealC.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 fe 81 ef 89 15 00 00 03 c7 31 03 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? 8b f0 83 c6 04 6a 00 e8 ?? ?? ?? ?? 03 f0 01 f3 8b 45 ec } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}