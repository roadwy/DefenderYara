
rule SoftwareBundler_Win32_ICLoader_I_bit{
	meta:
		description = "SoftwareBundler:Win32/ICLoader.I!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 ce 0b 22 d6 30 26 61 8b 45 08 40 3d 44 07 00 00 } //01 00 
		$a_01_1 = {6a 00 6a 00 6a 00 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 6a 00 6a 00 ff d6 } //00 00 
	condition:
		any of ($a_*)
 
}