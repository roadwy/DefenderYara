
rule Trojan_BAT_Injector_SC_bit{
	meta:
		description = "Trojan:BAT/Injector.SC!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 20 ff 00 00 00 5f d2 13 [0-80] 7e ?? 00 00 04 ?? ?? 11 ?? 61 d2 9c [0-03] 58 } //1
		$a_02_1 = {46 00 6f 00 72 00 6d 00 31 00 ?? ?? 53 00 69 00 73 00 74 00 69 00 6d 00 65 00 74 00 6f 00 20 00 49 00 6e 00 63 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}