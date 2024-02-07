
rule Trojan_Win32_Qakbot_PAF_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 3f 30 42 33 64 43 61 6d 65 72 61 40 40 51 41 45 40 41 42 56 30 40 40 5a } //01 00  n?0B3dCamera@@QAE@ABV0@@Z
		$a_01_1 = {6e 3f 30 42 33 64 54 72 61 6e 73 66 6f 72 6d 61 74 69 6f 6e 53 65 74 40 40 51 41 45 40 58 5a } //01 00  n?0B3dTransformationSet@@QAE@XZ
		$a_01_2 = {6e 3f 30 44 69 72 45 6e 74 72 79 40 40 51 41 45 40 57 34 44 69 72 45 6e 74 72 79 46 6c 61 67 40 40 40 5a } //01 00  n?0DirEntry@@QAE@W4DirEntryFlag@@@Z
		$a_01_3 = {6e 3f 30 49 4e 65 74 55 52 4c 4f 62 6a 65 63 74 40 40 51 41 45 40 41 42 56 30 40 40 5a } //01 00  n?0INetURLObject@@QAE@ABV0@@Z
		$a_01_4 = {6e 3f 30 50 6f 6c 79 67 6f 6e 40 40 51 41 45 40 41 42 56 52 65 63 74 61 6e 67 6c 65 40 40 40 5a } //01 00  n?0Polygon@@QAE@ABVRectangle@@@Z
		$a_01_5 = {6e 3f 35 40 59 41 41 41 56 53 76 53 74 72 65 61 6d 40 40 41 41 56 30 40 41 41 56 43 6f 6c 6f 72 40 40 40 5a } //0a 00  n?5@YAAAVSvStream@@AAV0@AAVColor@@@Z
		$a_01_6 = {70 72 69 6e 74 } //00 00  print
	condition:
		any of ($a_*)
 
}