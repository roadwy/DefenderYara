
rule Trojan_Win32_Fragtor_SPB_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.SPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 1c 08 89 4a 04 33 c0 40 8b 95 ?? ?? ff ff 03 f8 e9 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}