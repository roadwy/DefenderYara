
rule Trojan_Win32_StealC_D_MTB{
	meta:
		description = "Trojan:Win32/StealC.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {58 53 50 b8 ?? ?? ?? ?? 40 25 ?? ?? ?? ?? 35 ?? ?? ?? ?? 89 c3 58 43 81 eb ?? ?? ?? ?? 81 eb ?? ?? ?? ?? 01 de 5b 68 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}