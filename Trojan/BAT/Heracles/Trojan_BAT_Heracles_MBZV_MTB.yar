
rule Trojan_BAT_Heracles_MBZV_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 00 4e 00 32 00 43 00 44 00 43 00 35 00 90 01 01 00 90 01 01 00 30 00 36 00 90 00 } //1
		$a_01_1 = {63 68 72 6f 6d 65 4e 6f 74 45 6e 63 6f 64 65 2e 65 78 65 } //1 chromeNotEncode.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}