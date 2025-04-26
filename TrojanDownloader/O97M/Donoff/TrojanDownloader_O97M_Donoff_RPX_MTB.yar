
rule TrojanDownloader_O97M_Donoff_RPX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RPX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {22 73 65 74 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 6d 69 63 72 6f 73 6f 66 74 2e 78 6d 6c 68 74 74 70 22 29 73 65 74 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 73 68 65 6c 6c 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 3d 73 70 65 63 69 61 6c 70 61 74 68 2b 28 22 5c 71 76 71 6d 2e 22 29 2e 6f 70 65 6e 22 67 65 74 22 2c 28 22 68 3a 2f 2f 77 77 77 2e 64 2e 6d 2f 77 6d 2f 6a 6b 68 66 6a 68 6a 7a 64 6b 68 68 71 7a 64 76 6a 7a 76 6a 62 64 6a 76 68 62 6b 62 7a 64 67 64 67 64 68 68 76 2f 6a 62 67 68 76 6b 67 6b 6a 68 6a 64 68 6a 64 6a 67 6a 62 6b 68 76 67 77 76 67 71 67 2e 22 29 2c 66 61 6c 73 65 2e 73 65 6e 64 3d 2e 72 65 73 70 6f 6e 73 65 62 6f 64 79 69 66 2e 73 74 61 74 75 73 3d 32 30 30 } //1 "set=createobject("microsoft.xmlhttp")set=createobject("shell.application")=specialpath+("\qvqm.").open"get",("h://www.d.m/wm/jkhfjhjzdkhhqzdvjzvjbdjvhbkbzdgdgdhhv/jbghvkgkjhjdhjdjgjbkhvgwvgqg."),false.send=.responsebodyif.status=200
	condition:
		((#a_01_0  & 1)*1) >=1
 
}