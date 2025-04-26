
rule Trojan_Win32_Bandra_EM_MTB{
	meta:
		description = "Trojan:Win32/Bandra.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e0 03 8a 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 81 f9 7e 07 00 00 72 e6 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}