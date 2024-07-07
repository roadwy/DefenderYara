
rule VirTool_Win32_Rekcap_B{
	meta:
		description = "VirTool:Win32/Rekcap.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 40 52 51 a3 90 01 04 ff d0 90 0a 50 00 68 90 01 04 50 90 02 23 ff 15 90 01 04 8b 90 01 05 8d 90 01 03 8b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}