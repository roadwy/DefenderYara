
rule Trojan_BAT_Netwire_WYM_MTB{
	meta:
		description = "Trojan:BAT/Netwire.WYM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 03 11 06 91 07 11 06 07 8e 69 5d 91 61 08 61 d2 6f ?? ?? ?? 0a 00 00 11 06 17 58 } //1
		$a_01_1 = {61 73 66 73 61 66 73 61 66 73 } //1 asfsafsafs
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}