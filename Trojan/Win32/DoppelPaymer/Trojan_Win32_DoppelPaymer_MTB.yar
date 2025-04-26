
rule Trojan_Win32_DoppelPaymer_MTB{
	meta:
		description = "Trojan:Win32/DoppelPaymer!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {51 8d 4e 34 e8 ?? ?? ff ff 8b 08 e8 ?? ?? ff ff 35 ?? ?? ?? ?? 8d 4d dc 89 46 3c e8 ?? ?? ff ff 8b 57 48 8b 45 f4 89 56 20 89 46 40 8b 4f 50 6a ff 89 4e 28 8b 4d fc 56 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}