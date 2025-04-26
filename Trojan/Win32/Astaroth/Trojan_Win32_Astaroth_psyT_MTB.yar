
rule Trojan_Win32_Astaroth_psyT_MTB{
	meta:
		description = "Trojan:Win32/Astaroth.psyT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 af fe a2 35 d8 0c ec 3e 03 b2 35 6a 4e fd d0 e1 bb 67 bc 89 5b 84 73 e1 e3 30 14 e0 dd bc 5d 69 31 63 9f 46 5a 8e 81 a8 9e 6c 2d f1 32 64 54 23 71 ce } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}