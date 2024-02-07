
rule SoftwareBundler_Win32_Trawlmernib{
	meta:
		description = "SoftwareBundler:Win32/Trawlmernib,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 3f 41 56 52 61 6d 62 6c 65 72 50 61 67 65 40 40 } //01 00  .?AVRamblerPage@@
		$a_01_1 = {52 00 55 00 70 00 64 00 61 00 74 00 65 00 5f 00 25 00 73 00 2e 00 65 00 78 00 65 00 00 00 } //01 00 
		$a_01_2 = {64 00 6c 00 2e 00 7a 00 76 00 75 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2f 00 } //00 00  dl.zvu.com/pinstall/
	condition:
		any of ($a_*)
 
}
rule SoftwareBundler_Win32_Trawlmernib_2{
	meta:
		description = "SoftwareBundler:Win32/Trawlmernib,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 52 61 6d 62 6c 65 72 20 73 65 61 72 63 68 20 62 79 20 64 65 66 61 75 6c 74 } //01 00  Set Rambler search by default
		$a_01_1 = {26 00 70 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 3d 00 25 00 73 00 26 00 70 00 65 00 78 00 69 00 74 00 63 00 6f 00 64 00 65 00 3d 00 25 00 73 00 26 00 70 00 72 00 65 00 73 00 75 00 6c 00 74 00 3d 00 25 00 73 00 26 00 63 00 61 00 6d 00 70 00 61 00 69 00 67 00 6e 00 5f 00 69 00 64 00 3d 00 25 00 73 00 00 00 } //01 00 
		$a_01_2 = {76 6b 6d 75 73 69 63 2e 72 75 2f 56 4b 4d 55 53 49 43 73 65 74 75 70 2e 65 78 65 } //00 00  vkmusic.ru/VKMUSICsetup.exe
	condition:
		any of ($a_*)
 
}
rule SoftwareBundler_Win32_Trawlmernib_3{
	meta:
		description = "SoftwareBundler:Win32/Trawlmernib,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 52 61 6d 62 6c 65 72 20 73 65 61 72 63 68 20 62 79 20 64 65 66 61 75 6c 74 00 } //0a 00 
		$a_01_1 = {64 00 6c 00 2e 00 6d 00 69 00 6e 00 69 00 6c 00 6f 00 61 00 64 00 2e 00 6f 00 72 00 67 00 2f 00 70 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2f 00 52 00 55 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 00 00 } //01 00 
		$a_01_2 = {70 69 6e 73 74 61 6c 6c 3d 22 72 61 6d 62 6c 65 72 22 20 70 70 61 72 61 6d 73 } //01 00  pinstall="rambler" pparams
		$a_01_3 = {70 69 6e 73 74 61 6c 6c 3d 72 61 6d 62 6c 65 72 26 63 61 6d 70 61 69 67 6e 5f 69 64 3d } //00 00  pinstall=rambler&campaign_id=
	condition:
		any of ($a_*)
 
}