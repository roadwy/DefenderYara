
rule Trojan_Win32_Dridex_UYZ_MTB{
	meta:
		description = "Trojan:Win32/Dridex.UYZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 f9 8b 7c 24 20 8b 74 24 08 8a 1c 37 81 e1 ff 00 00 00 8b 74 24 18 32 1c 0e 8b 4c 24 1c 8b 74 24 08 88 1c 31 83 c6 01 8b 4c 24 ?? 39 ce 8b 4c 24 04 89 4c 24 0c 89 74 24 10 89 54 24 14 0f 84 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}