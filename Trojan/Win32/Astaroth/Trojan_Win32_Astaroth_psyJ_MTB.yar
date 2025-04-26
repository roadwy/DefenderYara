
rule Trojan_Win32_Astaroth_psyJ_MTB{
	meta:
		description = "Trojan:Win32/Astaroth.psyJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {67 00 6c 00 69 00 73 00 00 00 b0 04 02 00 ff ff ff ff 05 00 00 00 75 00 73 00 74 00 72 00 61 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}