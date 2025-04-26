
rule Ransom_Win32_StopCrypt_PAO_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c8 8b 45 ?? c1 e8 05 89 45 ?? 8b 45 ?? 33 f1 8b 8d ?? ?? ?? ?? 03 c1 33 c6 83 3d ?? ?? ?? ?? 27 c7 05 ?? ?? ?? ?? 2e ce 50 91 89 45 ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}