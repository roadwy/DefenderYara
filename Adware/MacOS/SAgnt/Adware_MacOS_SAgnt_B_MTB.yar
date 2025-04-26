
rule Adware_MacOS_SAgnt_B_MTB{
	meta:
		description = "Adware:MacOS/SAgnt.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 70 69 2e 6d 61 63 2e 66 6c 6d 67 72 2e 6e 65 74 } //5 api.mac.flmgr.net
		$a_01_1 = {2f 68 6f 6d 65 70 61 67 65 42 6f 6f 6b 6d 61 72 6b 2e 73 68 20 2d 75 70 64 61 74 65 4d 61 72 6b 55 72 6c 4d 61 74 63 68 } //1 /homepageBookmark.sh -updateMarkUrlMatch
		$a_01_2 = {63 6f 6d 2e 79 64 73 64 2e 59 44 53 74 65 77 61 72 64 } //1 com.ydsd.YDSteward
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}