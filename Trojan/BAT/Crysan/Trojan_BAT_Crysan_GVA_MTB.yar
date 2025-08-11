
rule Trojan_BAT_Crysan_GVA_MTB{
	meta:
		description = "Trojan:BAT/Crysan.GVA!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {3a 00 2f 00 2f 00 61 00 70 00 73 00 74 00 6f 00 72 00 69 00 2e 00 72 00 75 00 2f 00 70 00 61 00 6e 00 65 00 6c 00 } //2 ://apstori.ru/panel
		$a_01_1 = {52 00 67 00 79 00 4e 00 4f 00 37 00 46 00 71 00 6e 00 } //1 RgyNO7Fqn
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}