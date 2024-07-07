
rule Backdoor_Linux_Gafgyt_AO_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.AO!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 54 53 4f 54 53 54 54 53 4b 54 53 49 54 53 4c 54 53 4c } //2 BTSOTSTTSKTSITSLTSL
		$a_01_1 = {4b 54 53 69 54 53 6c 54 53 6c 54 53 69 54 53 6e 54 53 67 54 53 20 54 53 42 54 53 6f 54 53 74 54 53 73 } //1 KTSiTSlTSlTSiTSnTSgTS TSBTSoTStTSs
		$a_01_2 = {55 54 53 44 54 53 50 } //1 UTSDTSP
		$a_01_3 = {48 54 53 4f 54 53 4f 54 53 44 54 53 41 54 53 53 54 53 53 54 53 53 54 53 48 54 53 49 54 53 54 } //1 HTSOTSOTSDTSATSSTSSTSSTSHTSITST
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}