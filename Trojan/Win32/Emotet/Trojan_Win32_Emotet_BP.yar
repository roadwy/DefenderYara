
rule Trojan_Win32_Emotet_BP{
	meta:
		description = "Trojan:Win32/Emotet.BP,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {68 65 23 40 31 2e 50 64 62 } //3 he#@1.Pdb
		$a_01_1 = {53 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 } //1 S Corpora
		$a_01_2 = {53 00 51 00 4c 00 43 00 45 00 4f 00 4c 00 45 00 44 00 } //1 SQLCEOLED
	condition:
		((#a_00_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}