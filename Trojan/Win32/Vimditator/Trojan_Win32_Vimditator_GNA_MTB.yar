
rule Trojan_Win32_Vimditator_GNA_MTB{
	meta:
		description = "Trojan:Win32/Vimditator.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cd 8b d1 8d 74 24 ?? 8d 7c 18 ?? 6a 0a c1 e9 ?? f3 a5 8b ca 83 e1 ?? f3 a4 8b 7b ?? 8b 35 ?? ?? ?? ?? 03 fd 89 7b ?? ff d6 6a 0a ff d6 6a 0a ff d6 81 7b ?? 78 da 04 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}