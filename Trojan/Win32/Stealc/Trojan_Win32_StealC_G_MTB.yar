
rule Trojan_Win32_StealC_G_MTB{
	meta:
		description = "Trojan:Win32/StealC.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 f1 81 c1 ?? ?? ?? ?? 31 01 59 51 b9 ?? ?? ?? ?? 01 f1 01 19 8b 0c ?? 55 89 e5 81 c5 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}