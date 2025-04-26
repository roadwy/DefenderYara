
rule Trojan_Win32_Astaroth_psyG_MTB{
	meta:
		description = "Trojan:Win32/Astaroth.psyG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 15 18 20 40 00 a3 2c 33 40 00 8d 4d fc 50 51 ff 15 78 20 40 00 ff 15 00 20 40 00 8b 45 04 a3 9b 31 40 00 33 c0 b9 16 00 00 00 50 49 75 fc 68 00 7f 00 00 56 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}