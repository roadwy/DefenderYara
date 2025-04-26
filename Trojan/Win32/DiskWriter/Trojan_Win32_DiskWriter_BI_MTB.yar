
rule Trojan_Win32_DiskWriter_BI_MTB{
	meta:
		description = "Trojan:Win32/DiskWriter.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 00 00 00 10 68 d0 30 41 00 e8 27 28 ff ff 8b d8 6a 00 68 d0 88 41 00 68 00 30 00 00 68 d4 88 41 00 53 e8 1e 29 ff ff 53 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}