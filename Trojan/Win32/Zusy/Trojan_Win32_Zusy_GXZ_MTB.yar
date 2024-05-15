
rule Trojan_Win32_Zusy_GXZ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 65 74 6c 69 66 74 65 6e 5c 73 65 63 69 76 72 65 53 5c 74 65 53 6c 6f 72 74 6e 6f 43 74 6e 65 72 72 75 43 5c 4d 45 54 53 59 53 73 } //01 00  retliften\secivreS\teSlortnoCtnerruC\METSYSs
		$a_01_1 = {6e 69 61 6d 6f 44 6e 69 67 6f 4c } //01 00  niamoDnigoL
		$a_01_2 = {65 70 79 74 79 61 6c 70 73 69 44 65 63 72 75 6f 73 65 52 } //01 00  epytyalpsiDecruoseR
		$a_01_3 = {65 70 79 54 73 73 65 72 64 64 41 72 65 6c 6c 6f 72 74 6e 6f 43 6e 69 61 6d 6f 44 } //01 00  epyTsserddArellortnoCniamoD
		$a_80_4 = {73 74 6f 70 69 66 79 2e 63 6f 2f 6e 65 77 73 2e 70 68 70 3f 74 69 64 3d 4a 42 42 36 39 48 2e 6a 70 67 } //stopify.co/news.php?tid=JBB69H.jpg  01 00 
		$a_01_5 = {5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 62 69 6e 2e 65 78 65 } //01 00  \AppData\Local\Temp\bin.exe
		$a_01_6 = {2f 74 73 6f 48 62 72 4b 64 65 74 63 69 72 74 73 65 52 } //00 00  /tsoHbrKdetcirtseR
	condition:
		any of ($a_*)
 
}