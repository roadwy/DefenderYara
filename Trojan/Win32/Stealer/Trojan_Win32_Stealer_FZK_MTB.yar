
rule Trojan_Win32_Stealer_FZK_MTB{
	meta:
		description = "Trojan:Win32/Stealer.FZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 cc 8b 42 0c 8b 4d dc 8b 51 0c 8b 8d ?? ?? ?? ?? 8b b5 00 ff ff ff 8a 04 08 32 04 32 8b 4d cc 8b 51 0c 8b 8d f8 fe ff ff 88 04 0a c7 45 fc 0b 00 00 00 e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}