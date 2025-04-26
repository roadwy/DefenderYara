
rule Ransom_Win32_StopCrypt_SEB_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 ?? 03 c5 33 44 24 ?? 33 c8 2b f9 8d 44 24 ?? 89 4c 24 ?? 89 7c 24 ?? e8 ?? ?? ?? ?? 83 6c 24 ?? ?? 0f 85 ?? ?? ?? ?? 8b 84 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}