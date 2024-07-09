
rule Ransom_Win32_StopCrypt_SQ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 81 3d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}