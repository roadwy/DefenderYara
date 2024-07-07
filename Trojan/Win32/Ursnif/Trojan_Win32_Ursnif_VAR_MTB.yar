
rule Trojan_Win32_Ursnif_VAR_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.VAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 54 24 1c 81 c1 84 de 40 01 6a a6 58 2b c3 89 4c 24 18 2b c6 89 0d 90 01 04 03 e8 a1 90 01 04 f7 db 83 d7 00 89 8c 10 fb e4 ff ff f7 df 8b 44 24 28 3b 05 90 01 04 72 90 00 } //1
		$a_02_1 = {03 de 8d 7c 1b 40 05 90 01 01 5b c8 01 89 01 6a 43 59 2b ce 2b ca 03 f9 81 3d 90 01 04 7c 24 00 00 89 1d 90 01 04 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}