
rule Trojan_BAT_TrojanDownloader_IAG_MTB{
	meta:
		description = "Trojan:BAT/TrojanDownloader.IAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 04 00 00 "
		
	strings :
		$a_80_0 = {48 47 49 47 4a 47 51 50 52 50 53 50 54 50 55 50 56 50 57 50 58 50 59 50 5a 50 68 67 69 68 6a 67 6f 6e 70 6e 71 6e 72 6e } //HGIGJGQPRPSPTPUPVPWPXPYPZPhgihjgonpnqnrn  5
		$a_80_1 = {4f 5a 78 54 4b 58 75 76 73 6c 39 44 33 34 4c 57 68 50 } //OZxTKXuvsl9D34LWhP  5
		$a_80_2 = {53 4c 56 30 66 46 49 73 70 74 73 5a 74 6a 76 46 66 74 31 37 } //SLV0fFIsptsZtjvFft17  5
		$a_80_3 = {31 31 31 31 31 2d 32 32 32 32 32 2d 34 30 30 30 31 2d 30 30 30 30 31 } //11111-22222-40001-00001  2
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5+(#a_80_3  & 1)*2) >=17
 
}