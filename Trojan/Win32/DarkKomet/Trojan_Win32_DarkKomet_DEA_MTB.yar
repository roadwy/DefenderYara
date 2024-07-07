
rule Trojan_Win32_DarkKomet_DEA_MTB{
	meta:
		description = "Trojan:Win32/DarkKomet.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 e1 ff 00 00 00 8b 45 90 01 01 69 c0 90 01 04 99 be 90 01 04 f7 fe 33 d2 8a 94 05 90 01 04 33 ca 8b 45 90 01 01 69 c0 90 01 04 99 be 90 01 04 f7 fe 8b 55 90 01 01 88 0c 02 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}