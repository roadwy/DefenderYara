
rule Trojan_Win32_Farfli_MES_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 55 08 03 55 fc 8a 02 04 86 8b 4d 08 03 4d fc 88 01 8b 55 08 03 55 fc 8a 02 34 ?? 8b 4d 08 03 4d fc 88 01 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}