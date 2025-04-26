
rule Trojan_BAT_FormBook_NRE_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 28 16 00 00 0a 25 26 0b 28 ?? ?? ?? 0a 25 26 07 16 07 8e 69 6f ?? ?? ?? 0a 25 26 0a 28 ?? ?? ?? 0a 25 26 06 6f ?? ?? ?? 0a } //5
		$a_01_1 = {4a 47 46 44 53 48 54 45 4a 48 44 47 53 48 4a 45 52 46 48 44 47 } //1 JGFDSHTEJHDGSHJERFHDG
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}