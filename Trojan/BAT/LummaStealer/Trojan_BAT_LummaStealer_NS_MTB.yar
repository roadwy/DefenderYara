
rule Trojan_BAT_LummaStealer_NS_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 10 11 17 20 ef 85 2e d2 5a 20 4e 60 83 60 61 38 ?? ?? ff ff 11 07 18 d3 1a 5a 58 4b 18 64 13 13 16 13 14 11 17 20 09 68 5f 47 5a 20 38 51 13 af 61 } //2
		$a_03_1 = {1f 10 8d 2d 00 00 01 13 0d 16 13 15 11 17 20 6a 4e 74 80 5a 20 dd 49 27 d5 61 38 ?? ?? ff ff 11 0c 1f 0d 11 0c 1f 0d 95 11 0d 1f 0d 95 5a 9e 11 0c 1f 0e 11 0c 1f 0e 95 11 0d 1f 0e 95 58 9e 11 17 20 39 f7 ff 9c 5a 20 ef d0 3e 94 61 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}