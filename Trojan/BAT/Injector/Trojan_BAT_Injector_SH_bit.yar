
rule Trojan_BAT_Injector_SH_bit{
	meta:
		description = "Trojan:BAT/Injector.SH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {4d 00 69 00 74 00 74 00 65 00 6e 00 } //1 Mitten
		$a_00_1 = {56 00 69 00 72 00 74 00 6f 00 } //1 Virto
		$a_03_2 = {06 1b 58 7e [0-06] 8e 69 58 ?? 7e [0-07] 91 ?? 7e [0-07] 1f 1d 5d 91 ?? 1f 1f 5f 63 ?? ?? 28 [0-06] 13 04 7e [0-08] 11 04 28 [0-06] 9c } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}