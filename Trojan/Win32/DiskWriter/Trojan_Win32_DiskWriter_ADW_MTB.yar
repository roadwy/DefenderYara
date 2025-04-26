
rule Trojan_Win32_DiskWriter_ADW_MTB{
	meta:
		description = "Trojan:Win32/DiskWriter.ADW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d7 c1 ea 05 8d 0c 38 89 55 fc 8b 45 d8 01 45 fc 8b c7 c1 e0 04 03 45 e4 33 45 fc 33 c1 89 45 d4 8b 45 d4 29 45 f4 8b 45 e8 29 45 f8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}