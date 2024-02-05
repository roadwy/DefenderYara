
rule Ransom_Win32_ContiCrypt_LOD_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.LOD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 c2 33 d2 bb 00 04 00 00 f7 f3 42 81 c2 00 02 00 00 33 c9 0f c8 93 0f cb 87 de 0f ce 87 f7 0f cf } //00 00 
	condition:
		any of ($a_*)
 
}