
rule Trojan_Win32_Glupteba_CCHZ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.CCHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d0 8b 45 ?? 33 c2 8b 55 ?? 2b f8 89 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}