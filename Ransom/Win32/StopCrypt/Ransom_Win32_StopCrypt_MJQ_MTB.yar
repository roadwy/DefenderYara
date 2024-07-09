
rule Ransom_Win32_StopCrypt_MJQ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MJQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 ec 83 45 f8 64 29 45 f8 83 6d f8 64 8b 45 f8 8d 4d fc e8 ?? ?? ?? ?? 8b 45 e0 01 45 fc 8b 45 f8 8b 4d f0 8d 14 01 8b 4d f4 31 55 fc ff 75 fc d3 e8 03 c3 50 8d 45 fc 50 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}