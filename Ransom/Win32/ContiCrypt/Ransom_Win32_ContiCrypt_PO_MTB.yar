
rule Ransom_Win32_ContiCrypt_PO_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.PO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 ea 03 8d ?? ?? c1 e1 02 2b c1 8b 4d ?? 0f b6 44 ?? ?? 8d 0c 19 30 03 8d 5b 04 b8 ?? ?? ?? ?? f7 ?? 8b 4d ?? c1 ea 03 8d 04 ?? c1 e0 02 2b f0 0f b6 44 ?? ?? 30 43 fd 8d 04 ?? 3d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}