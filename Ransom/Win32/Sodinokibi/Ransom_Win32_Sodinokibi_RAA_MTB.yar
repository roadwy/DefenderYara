
rule Ransom_Win32_Sodinokibi_RAA_MTB{
	meta:
		description = "Ransom:Win32/Sodinokibi.RAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {e8 3b fd ff ff 8b 4c 24 04 30 04 0e b8 01 00 00 00 29 44 24 04 83 7c 24 04 00 } //1
		$a_02_1 = {6a 00 6a 00 6a 00 8d 54 24 ?? 52 6a 00 ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f b6 80 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 25 ff 00 00 00 81 3d ?? ?? ?? ?? 21 06 00 00 a3 ?? ?? ?? ?? 75 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}