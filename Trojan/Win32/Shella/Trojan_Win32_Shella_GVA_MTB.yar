
rule Trojan_Win32_Shella_GVA_MTB{
	meta:
		description = "Trojan:Win32/Shella.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 55 c8 0f be 45 ee 8b 4d b0 33 c8 89 4d b0 8a 55 ef 88 95 40 ff ff ff 80 bd 40 ff ff ff 00 74 1b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}