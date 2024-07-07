
rule Trojan_Win32_Astaroth_psyM_MTB{
	meta:
		description = "Trojan:Win32/Astaroth.psyM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 28 8b 45 08 03 45 0c 48 89 45 fc 8b 7d fc eb 14 8a 07 50 ff 75 14 ff 75 10 e8 8d ff ff ff 83 f8 00 75 0b 4f 3b 7d 08 73 e7 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}