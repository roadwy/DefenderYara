
rule TrojanDownloader_Win32_Vxidl_gen_C{
	meta:
		description = "TrojanDownloader:Win32/Vxidl.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 45 f0 50 68 05 00 00 20 53 ff 55 90 01 01 89 45 90 09 0d 00 c7 45 90 01 01 04 00 00 00 6a 00 8d 45 90 01 01 50 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}