
rule Trojan_Win32_Astaroth_psyO_MTB{
	meta:
		description = "Trojan:Win32/Astaroth.psyO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {56 8b 06 05 98 16 40 00 ff d0 5e 83 c6 04 eb f0 8b ff 33 0a 45 4d } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}