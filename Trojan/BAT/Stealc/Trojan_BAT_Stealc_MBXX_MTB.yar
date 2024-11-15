
rule Trojan_BAT_Stealc_MBXX_MTB{
	meta:
		description = "Trojan:BAT/Stealc.MBXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {5a 41 7a 73 61 72 75 69 6b 00 51 41 77 74 79 6b 75 69 6c 00 44 53 73 64 73 41 73 73 73 51 } //3 䅚獺牡極k䅑瑷歹極l卄摳䅳獳关
		$a_01_1 = {65 41 6e 67 6c 65 73 00 47 43 4d 00 43 6f 6e } //2
		$a_01_2 = {33 38 32 63 66 65 66 61 39 61 64 66 } //1 382cfefa9adf
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}