
rule Trojan_BAT_Remcos_AMAP_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AMAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 05 02 08 11 05 58 91 03 11 05 07 5d 91 61 d2 9c 00 11 05 17 58 13 05 11 05 09 fe 04 13 06 11 06 2d } //3
		$a_80_1 = {47 65 74 42 79 74 65 73 41 73 79 6e 63 } //GetBytesAsync  1
		$a_80_2 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 22 41 6c 69 73 20 43 6c 6f 75 64 22 20 2f 74 72 20 22 } //schtasks /create /tn "Alis Cloud" /tr "  1
	condition:
		((#a_01_0  & 1)*3+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=5
 
}