
rule Trojan_Win32_Formbook_PB_MTB{
	meta:
		description = "Trojan:Win32/Formbook.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 4d f8 8b 45 fc 6a 00 81 c1 00 80 c1 2a 68 80 96 98 00 15 21 4e 62 fe 50 51 e8 ?? ?? 00 00 83 fa 07 7c ?? 7f ?? 3d ff 6f 40 93 76 ?? 83 c8 ff 8b d0 8b 4d 08 85 c9 74 } //1
		$a_01_1 = {5c 47 6f 6c 64 65 72 6e 43 72 79 70 74 65 72 5c } //2 \GoldernCrypter\
		$a_00_2 = {4f 00 50 00 45 00 52 00 41 00 54 00 49 00 4f 00 4e 00 20 00 53 00 55 00 43 00 43 00 45 00 53 00 53 00 46 00 55 00 4c 00 21 00 21 00 } //2 OPERATION SUCCESSFUL!!
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*2+(#a_00_2  & 1)*2) >=5
 
}