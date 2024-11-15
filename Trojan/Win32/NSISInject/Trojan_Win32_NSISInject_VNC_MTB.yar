
rule Trojan_Win32_NSISInject_VNC_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.VNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {73 69 6c 6b 61 6c 69 6e 65 20 73 76 72 65 73 74 65 73 2e 65 78 65 } //1 silkaline svrestes.exe
		$a_81_1 = {62 72 69 6e 6b 65 72 6e 65 73 20 67 65 6e 64 61 72 6d 65 72 69 73 } //1 brinkernes gendarmeris
		$a_81_2 = {70 72 65 73 62 79 74 65 72 69 61 6e 73 6b 2e 72 64 62 } //1 presbyteriansk.rdb
		$a_81_3 = {56 65 6e 73 74 72 65 68 61 61 6e 64 73 61 72 62 65 6a 64 65 72 6e 65 2e 61 67 62 } //1 Venstrehaandsarbejderne.agb
		$a_81_4 = {53 6b 61 66 74 2e 47 65 6e } //1 Skaft.Gen
		$a_81_5 = {63 61 75 64 6f 74 69 62 69 61 6c } //1 caudotibial
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}