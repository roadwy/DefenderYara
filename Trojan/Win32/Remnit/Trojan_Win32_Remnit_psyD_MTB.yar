
rule Trojan_Win32_Remnit_psyD_MTB{
	meta:
		description = "Trojan:Win32/Remnit.psyD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 80 ec 6c 30 61 00 41 4a 8b da 81 eb 09 58 cd 2f 52 53 8b d4 81 42 00 09 58 cd 2f 5b 5a } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}