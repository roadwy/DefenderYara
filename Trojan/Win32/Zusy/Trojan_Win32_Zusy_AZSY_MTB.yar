
rule Trojan_Win32_Zusy_AZSY_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AZSY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {51 68 5e a7 c0 e3 8b 55 e8 8b 02 50 e8 ?? ?? ?? ?? 83 c4 0c 8b 4d e8 89 41 78 8b 45 e8 83 78 78 00 75 07 32 c0 e9 ?? ?? ?? ?? 8b 45 e8 8b 48 08 51 68 1e a7 1e 2f 8b 55 e8 8b 02 50 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}