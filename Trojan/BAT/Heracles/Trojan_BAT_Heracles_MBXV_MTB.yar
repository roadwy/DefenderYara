
rule Trojan_BAT_Heracles_MBXV_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBXV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 00 72 00 50 00 72 00 36 00 47 00 77 00 72 00 6a 00 46 00 6a 00 4d 00 69 00 42 00 75 00 6e 00 31 00 56 00 2e 00 78 00 32 00 47 00 79 00 53 00 49 00 62 00 35 00 68 00 6c 00 75 00 76 00 67 00 72 00 6b 00 46 00 49 00 6c 00 } //3 MrPr6GwrjFjMiBun1V.x2GySIb5hluvgrkFIl
		$a_01_1 = {61 58 64 6b 70 00 72 31 35 79 73 41 41 54 6e 78 44 } //2
		$a_01_2 = {52 65 76 65 72 73 65 00 6c 4b 78 46 48 50 } //1 敒敶獲e䭬䙸偈
		$a_01_3 = {6e 76 65 72 74 65 72 5f 64 65 66 61 75 6c 74 2e 65 78 } //1 nverter_default.ex
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}