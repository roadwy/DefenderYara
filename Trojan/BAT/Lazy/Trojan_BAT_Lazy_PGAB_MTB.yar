
rule Trojan_BAT_Lazy_PGAB_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PGAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 09 11 0b 58 20 ?? ?? ?? ?? 5d 13 0c 06 11 0c 06 11 0c 91 07 11 0c 11 09 58 20 ?? ?? ?? ?? 5d 91 61 7e ?? ?? 00 04 11 0b [0-05] 5d 91 61 d2 9c 11 0b 17 58 13 0b 11 0b 1f 10 } //9
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*9+(#a_01_1  & 1)*1) >=10
 
}