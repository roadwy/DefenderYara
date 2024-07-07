
rule Trojan_Win32_DiskWriter_MKV_MTB{
	meta:
		description = "Trojan:Win32/DiskWriter.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d0 89 55 a8 6a 00 e8 90 01 04 8b 55 a8 2b d0 8b 45 d4 31 10 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}