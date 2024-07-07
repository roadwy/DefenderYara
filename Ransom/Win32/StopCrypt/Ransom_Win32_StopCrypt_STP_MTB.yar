
rule Ransom_Win32_StopCrypt_STP_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.STP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 03 d3 8b 45 ec 31 45 fc 31 55 fc 2b 7d fc 81 45 e8 90 01 04 ff 4d dc 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}