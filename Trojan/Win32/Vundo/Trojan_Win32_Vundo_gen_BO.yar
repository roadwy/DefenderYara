
rule Trojan_Win32_Vundo_gen_BO{
	meta:
		description = "Trojan:Win32/Vundo.gen!BO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {75 07 32 c0 e9 dd 00 00 00 8d 45 fc 50 56 56 ff 33 89 75 fc 8b 35 90 01 04 ff d6 90 00 } //1
		$a_01_1 = {43 6f 6f 6b 69 65 54 65 72 6d 69 6e 61 74 6f 72 2e 64 6c 6c 00 72 } //1 潃歯敩敔浲湩瑡牯搮汬爀
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}