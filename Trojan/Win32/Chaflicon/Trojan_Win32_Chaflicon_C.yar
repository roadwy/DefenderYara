
rule Trojan_Win32_Chaflicon_C{
	meta:
		description = "Trojan:Win32/Chaflicon.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b 17 89 d0 33 d2 89 17 8b e8 ff d5 83 3f 00 75 ?? 83 3d ?? ?? ?? ?? 00 74 11 e8 } //1
		$a_00_1 = {5b 56 45 52 53 41 4f 4c 4f 41 44 45 52 5d } //1 [VERSAOLOADER]
		$a_00_2 = {5b 4c 49 4e 4b 43 4f 4e 54 41 44 4f } //1 [LINKCONTADO
		$a_00_3 = {5b 46 54 50 55 53 45 52 5d } //1 [FTPUSER]
		$a_00_4 = {5b 4c 49 4e 4b 45 58 45 5d } //1 [LINKEXE]
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}