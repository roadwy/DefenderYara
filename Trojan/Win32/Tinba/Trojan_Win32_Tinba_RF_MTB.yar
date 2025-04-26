
rule Trojan_Win32_Tinba_RF_MTB{
	meta:
		description = "Trojan:Win32/Tinba.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b ca 69 d2 ab 98 00 00 8b f0 2b f2 2b c8 8b d0 2b d6 83 e9 11 8d 8c 11 7f be 00 00 89 35 } //5
		$a_01_1 = {6e 6f 73 6e 6c 65 64 6f 6d 74 72 74 67 62 6f 6d 69 6e 6d 61 46 68 65 65 74 49 53 6d 74 42 65 2e 61 } //1 nosnledomtrtgbominmaFheetISmtBe.a
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}