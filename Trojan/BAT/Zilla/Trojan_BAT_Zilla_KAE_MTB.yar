
rule Trojan_BAT_Zilla_KAE_MTB{
	meta:
		description = "Trojan:BAT/Zilla.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 00 4b 00 45 00 59 00 5f 00 43 00 55 00 52 00 52 00 45 00 4e 00 54 00 5f 00 55 00 53 00 45 00 52 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 47 00 75 00 69 00 64 00 6f 00 41 00 75 00 73 00 69 00 6c 00 69 00 } //1 HKEY_CURRENT_USER\Software\GuidoAusili
		$a_01_1 = {47 00 75 00 69 00 64 00 6f 00 41 00 75 00 73 00 69 00 6c 00 69 00 2e 00 62 00 61 00 6b 00 } //1 GuidoAusili.bak
		$a_01_2 = {31 00 38 00 38 00 2e 00 32 00 31 00 33 00 2e 00 31 00 36 00 37 00 2e 00 32 00 34 00 38 00 } //1 188.213.167.248
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}