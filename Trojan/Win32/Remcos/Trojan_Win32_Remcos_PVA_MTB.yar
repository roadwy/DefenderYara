
rule Trojan_Win32_Remcos_PVA_MTB{
	meta:
		description = "Trojan:Win32/Remcos.PVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {0f b6 5c 1d fc 30 58 03 0f b6 1f 30 58 04 83 c1 05 83 c6 05 81 f9 05 5a 00 00 72 } //2
		$a_02_1 = {8b c8 83 e1 03 8a 4c 0d f8 30 8c 05 ?? ?? ff ff 40 3d 05 5a 00 00 72 } //2
		$a_00_2 = {5a 59 47 4d 42 56 43 4a 4a 57 42 55 5a 55 58 50 4e 44 48 57 48 44 48 41 5a 4a 4b 55 4f 4d 4b 46 43 56 59 4a 43 4c 59 57 41 48 51 55 45 5a 4f 41 55 } //1 ZYGMBVCJJWBUZUXPNDHWHDHAZJKUOMKFCVYJCLYWAHQUEZOAU
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*1) >=3
 
}