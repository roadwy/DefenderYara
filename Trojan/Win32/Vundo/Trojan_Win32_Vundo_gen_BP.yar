
rule Trojan_Win32_Vundo_gen_BP{
	meta:
		description = "Trojan:Win32/Vundo.gen!BP,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 89 45 } //02 00 
		$a_01_1 = {32 32 32 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 61 00 73 00 } //01 00  ㈲⸲汤l汄䍬湡湕潬摡潎w汄䝬瑥汃獡佳橢捥tas
		$a_01_2 = {42 49 4e 52 45 53 00 } //01 00 
		$a_01_3 = {42 00 49 00 4e 00 52 00 45 00 53 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}