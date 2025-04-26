
rule Trojan_MacOS_UpdateAgent_A{
	meta:
		description = "Trojan:MacOS/UpdateAgent.A,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {24 28 69 6f 72 65 67 20 2d 61 64 32 20 2d 63 20 49 4f 50 6c 61 74 66 6f 72 6d 45 78 70 65 72 74 44 65 76 69 63 65 7c 78 6d 6c 6c 69 6e 74 20 2d 2d 78 70 61 74 68 20 27 2f 2f 6b 65 79 5b 2e 3d 22 49 4f 50 6c 61 74 66 6f 72 6d 55 55 49 44 22 5d } //1 $(ioreg -ad2 -c IOPlatformExpertDevice|xmllint --xpath '//key[.="IOPlatformUUID"]
		$a_00_1 = {63 75 72 6c 20 2d 2d 72 65 74 72 79 20 35 20 2d 48 20 22 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 6a 73 6f 6e 3b 20 63 68 61 72 73 65 74 3d 55 54 46 2d 38 22 20 2d 58 20 50 4f 53 54 20 2d 64 } //1 curl --retry 5 -H "Content-Type: application/json; charset=UTF-8" -X POST -d
		$a_00_2 = {78 61 74 74 72 20 2d 72 20 2d 64 20 63 6f 6d 2e 61 70 70 6c 65 2e 71 75 61 72 61 6e 74 69 6e 65 20 2f 74 6d 70 2f } //1 xattr -r -d com.apple.quarantine /tmp/
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}