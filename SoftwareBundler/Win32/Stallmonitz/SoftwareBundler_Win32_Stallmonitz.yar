
rule SoftwareBundler_Win32_Stallmonitz{
	meta:
		description = "SoftwareBundler:Win32/Stallmonitz,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 63 6f 6f 63 74 64 6c 66 61 73 74 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f } //00 00  www.cooctdlfast.com/download.php?
	condition:
		any of ($a_*)
 
}
rule SoftwareBundler_Win32_Stallmonitz_2{
	meta:
		description = "SoftwareBundler:Win32/Stallmonitz,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {7b 74 6d 70 7d 5c 49 6e 73 74 61 6c 6c 2e 65 78 65 } //01 00  {tmp}\Install.exe
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6e 74 64 6c 7a 6f 6e 65 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f } //00 00  http://www.ntdlzone.com/download.php?
	condition:
		any of ($a_*)
 
}
rule SoftwareBundler_Win32_Stallmonitz_3{
	meta:
		description = "SoftwareBundler:Win32/Stallmonitz,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 43 42 53 74 75 62 2d 54 72 61 63 74 69 6f 6e 31 2e 65 78 65 } //01 00  \CBStub-Traction1.exe
		$a_01_1 = {2f 43 42 55 52 4c 3d 68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 61 70 72 31 33 73 6f 75 74 68 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f } //00 00  /CBURL=http://www.coapr13south.com/download.php?
	condition:
		any of ($a_*)
 
}
rule SoftwareBundler_Win32_Stallmonitz_4{
	meta:
		description = "SoftwareBundler:Win32/Stallmonitz,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 75 6e 20 64 61 74 61 5c 6d 74 72 2e 65 78 65 } //01 00  run data\mtr.exe
		$a_01_1 = {72 75 6e 77 61 69 74 20 64 61 74 61 5c 62 67 62 2e 65 78 65 20 2f 43 42 55 52 4c 3d 68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 6f 63 74 64 6c 66 61 73 74 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f } //00 00  runwait data\bgb.exe /CBURL=http://www.cooctdlfast.com/download.php?
	condition:
		any of ($a_*)
 
}
rule SoftwareBundler_Win32_Stallmonitz_5{
	meta:
		description = "SoftwareBundler:Win32/Stallmonitz,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {7b 61 70 70 7d 5c 43 42 53 74 75 62 2e 65 78 65 } //01 00  {app}\CBStub.exe
		$a_01_1 = {2f 43 42 55 52 4c 3d 68 74 74 70 3a 2f 2f 77 77 77 2e 6d 69 63 6b 79 66 61 73 74 64 6c 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f } //01 00  /CBURL=http://www.mickyfastdl.com/download.php?
		$a_01_2 = {2f 43 42 55 52 4c 3d 68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 6a 75 6c 79 66 61 73 74 64 6c 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f } //00 00  /CBURL=http://www.cojulyfastdl.com/download.php?
	condition:
		any of ($a_*)
 
}
rule SoftwareBundler_Win32_Stallmonitz_6{
	meta:
		description = "SoftwareBundler:Win32/Stallmonitz,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {7b 74 6d 70 7d 5c 73 74 75 62 } //0a 00  {tmp}\stub
		$a_01_1 = {25 73 25 64 5f 69 6e 73 74 61 6c 6c 2e 65 78 65 } //01 00  %s%d_install.exe
		$a_01_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 6f 63 74 31 33 68 65 6e 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f } //01 00  http://www.cooct13hen.com/download.php?
		$a_01_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 73 65 70 74 31 33 6a 65 74 74 79 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f } //01 00  http://www.cosept13jetty.com/download.php?
		$a_01_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 73 65 70 74 31 34 77 61 74 65 72 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f } //00 00  http://www.cosept14water.com/download.php?
	condition:
		any of ($a_*)
 
}