
rule Trojan_BAT_Injector_SB_bit{
	meta:
		description = "Trojan:BAT/Injector.SB!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {91 08 1b 58 07 8e 69 58 90 02 04 5f 63 20 ff 00 00 00 5f d2 61 d2 9c 90 00 } //1
		$a_01_1 = {41 00 33 00 64 00 71 00 33 00 64 00 65 00 65 00 35 00 34 00 66 00 } //1 A3dq3dee54f
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}