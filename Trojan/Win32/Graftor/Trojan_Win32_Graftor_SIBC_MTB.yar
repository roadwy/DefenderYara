
rule Trojan_Win32_Graftor_SIBC_MTB{
	meta:
		description = "Trojan:Win32/Graftor.SIBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 65 72 76 69 63 65 44 6c 6c } //10 ServiceDll
		$a_03_1 = {33 ff 5b 8a 46 ?? 8a 0e d0 e0 02 46 ?? 6a 04 d0 e1 02 4e ?? d0 e0 02 46 ?? 0f be c9 d0 e0 02 46 ?? 03 cf c1 e1 ?? 0f be c0 8d 84 08 ?? ?? ?? ?? 8b 4d ?? 50 ff 75 ?? e8 ?? ?? ?? ?? 83 45 ?? 04 83 c7 ?? 83 c6 ?? 4b 75 } //1
		$a_03_2 = {33 c0 39 44 24 0c 7e ?? 56 8b 74 24 0c 8b d0 c1 fa ?? 8a c8 8a 14 32 80 e1 ?? d2 fa 8b 4c 24 08 80 e2 ?? 88 14 08 40 3b 44 24 10 7c } //1
	condition:
		((#a_00_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=12
 
}