
rule Trojan_O97M_Obfuse_BJ{
	meta:
		description = "Trojan:O97M/Obfuse.BJ,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {28 22 62 51 42 7a 41 47 6b 41 5a 51 42 34 41 47 55 41 59 77 41 75 41 47 55 41 65 41 42 6c 41 43 41 41 4c 77 42 70 } //1 ("bQBzAGkAZQB4AGUAYwAuAGUAeABlACAALwBp
		$a_00_1 = {43 61 6c 6c 20 53 68 65 6c 6c 28 } //1 Call Shell(
		$a_00_2 = {3d 20 22 4d 49 43 72 4f 53 4f 46 54 2e 58 4d 4c 64 4f 4d 22 } //1 = "MICrOSOFT.XMLdOM"
		$a_00_3 = {29 20 26 20 43 68 72 24 28 } //1 ) & Chr$(
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}