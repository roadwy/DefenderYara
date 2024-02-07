
rule Trojan_MacOS_IceFog_B_MTB{
	meta:
		description = "Trojan:MacOS/IceFog.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 43 6f 6e 74 65 6e 74 73 2f 52 65 73 6f 75 72 63 65 73 2f 2e 6c 61 75 6e 63 68 64 2e 61 70 70 } //01 00  /Contents/Resources/.launchd.app
		$a_00_1 = {25 40 2f 75 70 6c 6f 61 64 2e 61 73 70 78 3f 66 69 6c 65 70 61 74 68 3d 6f 72 64 65 72 26 66 69 6c 65 6e 61 6d 65 3d 25 40 2e 6a 70 67 00 75 70 6c 6f 61 64 00 75 70 6c 6f 61 64 73 00 64 6f 77 6e 6c 6f 61 64 } //01 00 
		$a_00_2 = {48 43 48 6f 73 74 49 6e 66 00 48 43 4e 65 74 00 48 43 55 70 44 6f 77 6e 6c 6f 61 64 00 4b 65 79 4c 6f 67 67 65 72 } //00 00  䍈潈瑳湉f䍈敎t䍈灕潄湷潬摡䬀祥潌杧牥
	condition:
		any of ($a_*)
 
}