
rule Trojan_BAT_Sakeeya_CNP_MTB{
	meta:
		description = "Trojan:BAT/Sakeeya.CNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {13 05 02 28 ?? ?? ?? ?? 13 04 28 ?? ?? ?? ?? 11 05 11 04 16 11 04 8e b7 6f ?? ?? ?? ?? 6f ?? ?? ?? ?? 0a 06 0d } //5
		$a_01_1 = {43 00 72 00 37 00 52 00 6f 00 6e 00 61 00 6c 00 64 00 6f 00 } //1 Cr7Ronaldo
		$a_01_2 = {7a 00 69 00 64 00 65 00 6e 00 } //1 ziden
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}