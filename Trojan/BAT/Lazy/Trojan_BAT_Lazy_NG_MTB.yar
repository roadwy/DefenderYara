
rule Trojan_BAT_Lazy_NG_MTB{
	meta:
		description = "Trojan:BAT/Lazy.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {09 03 17 11 04 58 91 11 04 1e 5a 1f 1f 5f 62 58 0d 11 04 17 58 13 04 11 04 1a } //5
		$a_01_1 = {17 2a 06 1e 58 02 8e 69 3c 6c 00 00 00 02 06 91 1f 4d } //5
		$a_81_2 = {5f 63 72 79 70 74 65 64 2e 65 78 65 } //2 _crypted.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_81_2  & 1)*2) >=12
 
}