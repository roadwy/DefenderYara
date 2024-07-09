
rule Ransom_Win32_StopCrypt_PBK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b fe 8b 75 ?? 8b d7 c1 e2 ?? 03 55 ?? 8b c7 c1 e8 05 03 45 ?? 03 f7 33 d6 33 d0 2b da 81 3d [0-08] 00 00 c7 05 ?? ?? ?? ?? b4 21 e1 c5 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}