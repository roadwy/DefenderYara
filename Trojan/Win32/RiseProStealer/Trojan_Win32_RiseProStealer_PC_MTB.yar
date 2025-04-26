
rule Trojan_Win32_RiseProStealer_PC_MTB{
	meta:
		description = "Trojan:Win32/RiseProStealer.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ca 23 ce b8 [0-04] 3b ce ba [0-04] 0f 43 ce c1 e1 02 e8 [0-04] 8b 55 fc 24 0f 8d 4a ?? 32 c1 32 c3 88 44 15 ?? 42 89 55 fc 83 fa ?? 72 ?? 0f 57 c0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}