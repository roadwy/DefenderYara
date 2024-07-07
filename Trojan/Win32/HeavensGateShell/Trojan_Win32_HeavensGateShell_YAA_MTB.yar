
rule Trojan_Win32_HeavensGateShell_YAA_MTB{
	meta:
		description = "Trojan:Win32/HeavensGateShell.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4e 20 8b 46 28 31 04 11 83 c2 04 3b 56 24 72 ef } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}