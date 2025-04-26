
rule Ransom_Win32_StopCrypt_PG_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 45 ?? 33 45 ?? 8b 4d ?? 89 01 5d } //1
		$a_03_1 = {d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? c7 05 ?? ?? ?? ?? fc 03 cf ff 8b 4d ?? 51 8d 55 ?? 52 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}