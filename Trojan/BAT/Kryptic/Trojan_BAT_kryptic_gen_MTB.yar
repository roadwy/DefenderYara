
rule Trojan_BAT_kryptic_gen_MTB{
	meta:
		description = "Trojan:BAT/kryptic.gen!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_03_0 = {07 09 11 04 6f ?? ?? ?? ?? 13 06 08 12 06 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 11 04 17 58 13 04 11 04 07 6f ?? ?? ?? ?? 32 d8 } //10
		$a_01_1 = {47 65 74 4f 62 6a 65 63 74 } //1 GetObject
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_3 = {43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 CurrentDomain
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}