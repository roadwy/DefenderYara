
rule Trojan_Win32_Lycutosso_A{
	meta:
		description = "Trojan:Win32/Lycutosso.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 6f 70 79 46 69 6c 65 53 61 66 65 00 63 72 65 61 74 65 5f 64 69 72 5f 6c 69 6e 6b } //2 潃祰楆敬慓敦挀敲瑡彥楤彲楬歮
		$a_01_1 = {64 65 63 72 79 70 74 00 64 69 73 69 6e 66 65 63 74 00 69 6e 66 65 63 74 } //2 敤牣灹t楤楳普捥t湩敦瑣
		$a_03_2 = {b8 ff ff 00 00 66 89 01 46 81 fe 2a 2c 0a 00 7c ?? 83 c1 02 4a 75 } //1
		$a_03_3 = {80 e1 06 0f be c9 f7 d9 1b c9 f7 d1 85 c8 0f 84 ?? 00 00 00 8d 74 24 30 e8 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}