
rule Ransom_Win32_StopCrypt_PG_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 45 90 01 01 33 45 90 01 01 8b 4d 90 01 01 89 01 5d 90 00 } //1
		$a_03_1 = {d3 e8 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 c7 05 90 01 04 fc 03 cf ff 8b 4d 90 01 01 51 8d 55 90 01 01 52 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}