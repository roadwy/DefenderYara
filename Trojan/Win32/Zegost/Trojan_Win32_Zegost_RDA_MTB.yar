
rule Trojan_Win32_Zegost_RDA_MTB{
	meta:
		description = "Trojan:Win32/Zegost.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 4d f3 0f be 55 ff 0f be 45 f3 33 d0 88 55 ff 8b 4d d0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}