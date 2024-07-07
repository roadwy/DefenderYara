
rule Trojan_BAT_CinoshiStealer_C_MTB{
	meta:
		description = "Trojan:BAT/CinoshiStealer.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 fd a2 ff 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 ce 00 00 00 4e 00 00 00 16 02 00 00 db } //2
		$a_01_1 = {52 65 67 44 65 6c 65 74 65 4b 65 79 } //1 RegDeleteKey
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}