
rule Trojan_Win32_Emotet_AW_MTB{
	meta:
		description = "Trojan:Win32/Emotet.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 46 56 47 59 42 55 48 2e 44 4c 4c } //01 00  TFVGYBUH.DLL
		$a_01_1 = {45 64 72 63 66 76 74 55 6a 6b 66 67 } //01 00  EdrcfvtUjkfg
		$a_01_2 = {48 66 74 67 4f 6a 68 6e } //01 00  HftgOjhn
		$a_01_3 = {52 64 72 63 66 76 74 49 68 6e 75 42 67 79 } //00 00  RdrcfvtIhnuBgy
	condition:
		any of ($a_*)
 
}