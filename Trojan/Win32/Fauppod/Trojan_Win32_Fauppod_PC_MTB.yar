
rule Trojan_Win32_Fauppod_PC_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 3a 00 74 [0-04] ac 32 02 88 07 47 51 83 c4 ?? 42 89 c0 56 83 c4 ?? 83 e9 ?? 89 c0 85 c9 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}