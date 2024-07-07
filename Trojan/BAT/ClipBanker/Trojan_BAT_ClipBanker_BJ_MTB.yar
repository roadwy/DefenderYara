
rule Trojan_BAT_ClipBanker_BJ_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 4a 4d 39 4b 74 45 76 6d 30 72 41 32 52 33 57 31 33 4c 37 6b 77 53 6b 67 36 59 3d } //2 lJM9KtEvm0rA2R3W13L7kwSkg6Y=
		$a_01_1 = {75 38 58 46 2b 5a 2b 35 37 49 55 56 7a 62 2b 62 69 52 71 43 41 53 33 53 53 67 6f 3d } //2 u8XF+Z+57IUVzb+biRqCAS3SSgo=
		$a_01_2 = {56 00 32 00 6c 00 75 00 5a 00 47 00 39 00 33 00 63 00 30 00 46 00 77 00 63 00 47 00 78 00 70 00 59 00 32 00 46 00 30 00 61 00 57 00 39 00 75 00 4d 00 } //2 V2luZG93c0FwcGxpY2F0aW9uM
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}