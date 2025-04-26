
rule Ransom_Win32_AvaddonCrypt_SO_MTB{
	meta:
		description = "Ransom:Win32/AvaddonCrypt.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec ?? c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 90 08 00 02 8b ?? ?? 90 05 01 04 50 51 52 53 ff 15 ?? ?? ?? ?? 8b ?? ?? 90 05 01 04 50 51 52 53 ff 15 ?? ?? ?? ?? 8b ?? ?? 90 05 01 04 50 51 52 53 ff 15 ?? ?? ?? ?? 8b ?? ?? 90 05 01 04 50 51 52 53 ff 15 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}