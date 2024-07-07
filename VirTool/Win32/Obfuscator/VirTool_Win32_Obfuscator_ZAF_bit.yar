
rule VirTool_Win32_Obfuscator_ZAF_bit{
	meta:
		description = "VirTool:Win32/Obfuscator.ZAF!bit,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {e8 01 39 05 90 01 04 0f 84 90 09 15 00 eb 90 01 01 8a 15 90 01 04 80 f2 90 01 01 88 15 90 01 04 8b 45 90 01 01 83 90 00 } //1
		$a_01_1 = {c6 45 c4 61 c6 45 c5 75 c6 45 c6 78 c6 45 c7 53 c6 45 c8 65 c6 45 c9 74 c6 45 ca 56 c6 45 cb 6f c6 45 cc 6c c6 45 cd 75 c6 45 ce 6d c6 45 cf 65 c6 45 d0 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}