
rule Trojan_Win32_Raccoon_PC_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 89 45 ?? 6a 00 [0-0e] 2b d8 [0-0e] 2b d8 8b 45 ?? 31 18 6a 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}