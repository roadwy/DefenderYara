
rule Ransom_Win32_StopCrypt_PBA_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 90 01 04 6a 00 ff 15 90 01 04 e8 90 01 04 8b 4c 24 90 01 01 30 04 31 81 bc 24 90 01 04 91 05 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}