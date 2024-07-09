
rule Trojan_Win32_Fareit_BD_MTB{
	meta:
		description = "Trojan:Win32/Fareit.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {5e c7 45 64 ?? ?? 00 00 31 c9 31 ff 09 c7 ad 31 04 0f 83 e9 fc 81 f9 ?? ?? 00 00 75 f1 bb ?? ?? ?? ?? 31 d2 83 f2 04 31 1c 0f 29 d1 7d f4 ff e7 } //1
		$a_03_1 = {ad 83 f8 00 74 fa 81 38 ?? ?? ?? ?? 75 f2 81 78 04 ?? ?? ?? ?? 75 e9 31 db 53 53 53 54 68 00 00 04 00 52 51 54 89 85 ?? 00 00 00 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}