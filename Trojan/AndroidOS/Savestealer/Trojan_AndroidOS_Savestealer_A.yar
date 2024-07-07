
rule Trojan_AndroidOS_Savestealer_A{
	meta:
		description = "Trojan:AndroidOS/Savestealer.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 55 6c 71 64 6c 64 34 62 46 68 72 51 57 70 61 62 6b 77 30 63 7a 52 44 56 6d 56 47 56 56 46 69 54 31 4e 4d 61 47 39 31 4f 45 39 4e 55 55 35 33 5a 58 6b 35 54 30 31 50 53 55 6c 36 54 45 52 58 5a 47 51 } //2 WUlqdld4bFhrQWpabkw0czRDVmVGVVFiT1NMaG91OE9NUU53ZXk5T01PSUl6TERXZGQ
		$a_01_1 = {4d 70 4c 42 46 55 37 49 4d 62 46 65 54 75 76 46 } //2 MpLBFU7IMbFeTuvF
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}