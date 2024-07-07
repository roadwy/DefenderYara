
rule Trojan_BAT_Stealer_MVD_MTB{
	meta:
		description = "Trojan:BAT/Stealer.MVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {41 33 31 30 4c 6f 67 67 65 72 } //2 A310Logger
		$a_00_1 = {33 62 30 65 32 64 33 64 2d 33 64 36 36 2d 34 32 62 62 2d 38 66 39 63 2d 64 36 65 31 38 38 66 33 35 39 61 65 } //2 3b0e2d3d-3d66-42bb-8f9c-d6e188f359ae
		$a_80_2 = {6b 65 79 34 2e 64 62 } //key4.db  1
		$a_80_3 = {4c 6f 67 69 6e 20 44 61 74 61 } //Login Data  1
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}