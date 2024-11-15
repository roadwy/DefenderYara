
rule Trojan_BAT_Stealer_AYB_MTB{
	meta:
		description = "Trojan:BAT/Stealer.AYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 18 6a 11 15 6e 5a 6d 13 16 11 16 6e 11 1a 6a 61 69 13 18 11 19 6e 11 1a 6a 61 69 13 1a 08 17 58 20 00 01 00 00 5d 0c 09 06 08 91 58 20 00 01 00 00 5d 0d } //2
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_2 = {24 33 37 35 63 35 65 66 66 2d 30 36 35 30 2d 34 33 30 31 2d 38 35 65 66 2d 33 38 32 63 66 65 66 61 39 61 64 66 } //1 $375c5eff-0650-4301-85ef-382cfefa9adf
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}