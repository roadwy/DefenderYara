
rule VirTool_Win32_Injector_IE_bit{
	meta:
		description = "VirTool:Win32/Injector.IE!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ce 03 c8 8a 09 88 0c 02 8d 48 01 33 4b 04 51 33 c9 8a 0c 02 5f 2b cf 88 0c 02 8d 48 01 33 0b 51 33 c9 8a 0c 02 5f 2b cf 88 0c 02 40 90 01 06 75 cb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}