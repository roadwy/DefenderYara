
rule Trojan_Win32_FrostLizzard_C_dha{
	meta:
		description = "Trojan:Win32/FrostLizzard.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 8b 40 30 8b 4d e8 66 0f be 04 08 8b 4d e8 8b 55 b0 66 89 04 4a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}