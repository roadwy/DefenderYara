
rule Trojan_Win32_Dejandet_G_MTB{
	meta:
		description = "Trojan:Win32/Dejandet.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {64 a1 30 00 00 00 8b f0 8a 40 02 84 c0 75 [0-70] 8b 46 68 83 e0 70 85 c0 75 ?? 8b 46 18 8b 40 10 85 c0 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}