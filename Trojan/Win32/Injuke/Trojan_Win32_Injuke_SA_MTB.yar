
rule Trojan_Win32_Injuke_SA_MTB{
	meta:
		description = "Trojan:Win32/Injuke.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a d3 2a d1 80 e2 ?? 32 13 32 d0 88 13 03 df 3b 5d ?? 72 ?? 46 ff 4d ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}