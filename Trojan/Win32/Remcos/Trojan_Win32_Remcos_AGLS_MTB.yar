
rule Trojan_Win32_Remcos_AGLS_MTB{
	meta:
		description = "Trojan:Win32/Remcos.AGLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 dc 03 55 b4 8b 45 d4 03 45 b0 8b 4d c0 e8 ?? ?? ?? ?? 8b 45 c0 01 45 b0 8b 45 c0 01 45 b4 8b 45 bc 01 45 b4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}