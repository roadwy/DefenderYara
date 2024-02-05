
rule SoftwareBundler_Win32_Prepscram_BA_MTB{
	meta:
		description = "SoftwareBundler:Win32/Prepscram.BA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 20 89 7d c8 8a 0c 06 8b c6 f7 75 14 8b 45 08 88 4d 0f 8a 04 02 32 c1 8b 4d 18 88 04 0e 8b 45 bc 89 45 ec 8b 45 d4 89 45 fc } //00 00 
	condition:
		any of ($a_*)
 
}