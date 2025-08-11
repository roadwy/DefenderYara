
rule Trojan_BAT_Zusy_PGZU_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PGZU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 0a 8f ?? 00 00 01 25 47 08 d2 61 d2 52 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 05 8e 69 32 cd } //1
		$a_01_1 = {73 00 65 00 72 00 76 00 65 00 72 00 31 00 2e 00 65 00 78 00 65 } //4
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*4) >=5
 
}