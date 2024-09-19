
rule Trojan_Win32_Remcos_AREM_MTB{
	meta:
		description = "Trojan:Win32/Remcos.AREM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 7c d6 83 58 35 33 34 55 bf 64 d2 8c 02 ?? ?? ?? ?? bf 45 d5 8f 07 37 35 37 56 b8 7b df 8e ?? ?? ?? ?? 50 b8 65 dc 89 51 32 33 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}