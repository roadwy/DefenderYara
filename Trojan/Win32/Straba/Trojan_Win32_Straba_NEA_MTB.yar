
rule Trojan_Win32_Straba_NEA_MTB{
	meta:
		description = "Trojan:Win32/Straba.NEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 54 52 56 59 55 42 59 2e 44 4c 4c 00 49 62 76 79 45 78 64 76 67 00 4f 69 62 68 52 74 63 66 00 49 62 68 75 67 76 79 52 79 76 67 68 } //01 00  呃噒啙奂䐮䱌䤀癢䕹摸杶伀扩剨捴f扉畨癧剹癹桧
		$a_01_1 = {54 52 43 41 47 55 42 2e 44 4c 4c 00 48 76 67 66 63 44 62 68 6e 00 4f 68 62 67 44 63 74 66 00 4a 62 68 75 67 44 66 76 79 67 } //00 00 
	condition:
		any of ($a_*)
 
}