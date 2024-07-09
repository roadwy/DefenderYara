
rule Ransom_Win32_StopCrypt_MQK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MQK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 55 ?? 8b 85 08 fe ff ff 01 45 90 1b 01 8b 4d 90 1b 01 33 cb 33 4d e8 8d 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}