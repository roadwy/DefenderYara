
rule Trojan_Win64_Rhadamanthys_FIF_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.FIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 03 d1 48 8b ca 0f b6 09 33 c8 8b c1 48 8b 8d 28 01 00 00 48 8b 95 98 ?? ?? ?? 48 03 d1 48 8b ca 88 01 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}