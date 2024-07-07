
rule Ransom_Win32_ContiCrypt_PO_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.PO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 ea 03 8d 90 01 02 c1 e1 02 2b c1 8b 4d 90 01 01 0f b6 44 90 01 02 8d 0c 19 30 03 8d 5b 04 b8 90 01 04 f7 90 01 01 8b 4d 90 01 01 c1 ea 03 8d 04 90 01 01 c1 e0 02 2b f0 0f b6 44 90 01 02 30 43 fd 8d 04 90 01 01 3d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}