
rule Trojan_Win32_Emotet_AW_MTB{
	meta:
		description = "Trojan:Win32/Emotet.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 46 56 47 59 42 55 48 2e 44 4c 4c } //1 TFVGYBUH.DLL
		$a_01_1 = {45 64 72 63 66 76 74 55 6a 6b 66 67 } //1 EdrcfvtUjkfg
		$a_01_2 = {48 66 74 67 4f 6a 68 6e } //1 HftgOjhn
		$a_01_3 = {52 64 72 63 66 76 74 49 68 6e 75 42 67 79 } //1 RdrcfvtIhnuBgy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}