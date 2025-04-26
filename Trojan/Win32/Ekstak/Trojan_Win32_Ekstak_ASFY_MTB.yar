
rule Trojan_Win32_Ekstak_ASFY_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 04 56 56 8d 4c 24 10 56 51 56 52 c7 44 24 2c 02 00 00 00 c7 44 24 20 01 00 00 00 ff 15 ?? ?? ?? 00 8b f0 8b 44 24 04 f7 de 1b f6 50 f7 de ff 15 } //5
		$a_03_1 = {6a 00 52 6a 00 50 c7 44 24 ?? 02 00 00 00 c7 44 24 ?? 01 00 00 00 ff 15 ?? ?? ?? 00 8b 4c 24 08 8b f0 f7 de 1b f6 51 f7 de ff 15 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}