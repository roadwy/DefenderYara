
rule Trojan_BAT_Lazy_AMMB_MTB{
	meta:
		description = "Trojan:BAT/Lazy.AMMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {15 16 16 7e ?? 00 00 04 11 07 8f ?? 00 00 01 7e ?? 00 00 04 16 12 06 } //2
		$a_80_1 = {61 32 56 79 62 6d 56 73 4d 7a 49 75 5a 47 78 73 } //a2VybmVsMzIuZGxs  1
	condition:
		((#a_03_0  & 1)*2+(#a_80_1  & 1)*1) >=3
 
}