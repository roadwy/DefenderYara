
rule Trojan_BAT_Hawkeye_AHE_MTB{
	meta:
		description = "Trojan:BAT/Hawkeye.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 0a 2b 37 02 50 06 02 50 8e b7 5d 02 50 06 02 50 8e b7 5d 91 03 06 03 8e b7 5d 91 61 02 50 06 17 d6 02 50 8e b7 5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 06 17 d6 0a 06 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Hawkeye_AHE_MTB_2{
	meta:
		description = "Trojan:BAT/Hawkeye.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 2b 20 09 65 1a 5d 2c 11 28 ?? ?? ?? 06 8e 69 1b 59 17 58 8d 05 00 00 01 0c 09 17 58 0d 09 1f 64 31 c1 } //2
		$a_01_1 = {73 00 6f 00 63 00 72 00 75 00 41 00 2e 00 65 00 78 00 65 00 } //1 socruA.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}