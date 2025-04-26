
rule Trojan_Win32_CoinStealer_BD_MTB{
	meta:
		description = "Trojan:Win32/CoinStealer.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {cc f7 d0 cc 8b 54 24 08 33 c8 e9 } //1
		$a_01_1 = {33 c8 33 c8 33 c8 33 c8 33 c8 33 c8 64 89 0d } //1
		$a_01_2 = {45 6c 69 6d 69 6e 61 6d 6f 73 20 6c 6f 73 20 76 69 72 75 73 20 61 72 72 61 6e 63 61 6e 64 6f } //1 Eliminamos los virus arrancando
		$a_01_3 = {65 6c 69 6d 69 6e 61 72 20 63 75 61 6c 71 75 69 65 72 20 76 69 72 75 73 } //1 eliminar cualquier virus
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}