
rule Ransom_Win32_Sodinokibi_A{
	meta:
		description = "Ransom:Win32/Sodinokibi.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {53 56 8b da 33 f6 57 8b f9 85 db 7e 0d e8 0f fd ff ff 30 04 3e 46 3b f3 7c f3 } //1
		$a_02_1 = {33 c0 3d c4 36 4f 00 75 0c 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 40 3d f2 70 86 00 7c e5 ff 15 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}