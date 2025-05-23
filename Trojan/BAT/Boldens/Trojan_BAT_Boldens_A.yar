
rule Trojan_BAT_Boldens_A{
	meta:
		description = "Trojan:BAT/Boldens.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 00 52 00 45 00 53 00 55 00 4c 00 54 00 20 00 30 00 78 00 63 00 38 00 30 00 30 00 30 00 32 00 32 00 32 00 } //1 HRESULT 0xc8000222
		$a_03_1 = {5c 00 49 00 6e 00 74 00 65 00 72 00 66 00 61 00 63 00 65 00 73 00 5c 00 ?? ?? 5c 00 ?? ?? 4e 00 61 00 6d 00 65 00 53 00 65 00 72 00 76 00 65 00 72 00 [0-20] 2c 00 38 00 2e 00 38 00 2e 00 38 00 2e 00 38 00 } //1
		$a_03_2 = {50 00 4f 00 53 00 54 00 ?? ?? 6e 00 61 00 6d 00 65 00 3d 00 4a 00 69 00 6d 00 26 00 61 00 67 00 65 00 3d 00 32 00 37 00 26 00 70 00 69 00 7a 00 7a 00 61 00 3d 00 73 00 75 00 61 00 73 00 61 00 67 00 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}