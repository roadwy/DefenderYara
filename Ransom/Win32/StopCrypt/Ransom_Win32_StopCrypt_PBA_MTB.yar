
rule Ransom_Win32_StopCrypt_PBA_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4c 24 ?? 30 04 31 81 bc 24 ?? ?? ?? ?? 91 05 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}