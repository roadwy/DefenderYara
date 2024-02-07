
rule Trojan_MacOS_Agent_A{
	meta:
		description = "Trojan:MacOS/Agent.A,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 22 24 28 69 6f 72 65 67 20 2d 61 64 32 20 2d 63 20 49 4f 50 6c 61 74 66 6f 72 6d 45 78 70 65 72 74 44 65 76 69 63 65 20 7c 20 78 6d 6c 6c 69 6e 74 20 2d 2d 78 70 61 74 68 20 27 2f 2f 6b 65 79 5b 2e 3d 22 49 4f 50 6c 61 74 66 6f 72 6d 55 55 49 44 22 5d 2f 66 6f 6c 6c 6f 77 69 6e 67 2d 73 69 62 6c 69 6e 67 3a 3a 2a 5b 31 5d 2f 74 65 78 74 28 29 27 20 2d 29 22 3b 43 4f 4e 54 45 4e 54 3d 24 28 63 75 72 6c 20 2d 2d 63 6f 6e 6e 65 63 74 2d 74 69 6d 65 6f 75 74 20 39 30 30 20 2d 4c 20 22 68 74 74 70 73 3a 2f 2f } //01 00  ="$(ioreg -ad2 -c IOPlatformExpertDevice | xmllint --xpath '//key[.="IOPlatformUUID"]/following-sibling::*[1]/text()' -)";CONTENT=$(curl --connect-timeout 900 -L "https://
		$a_00_1 = {3b 65 76 61 6c 20 22 24 43 4f 4e 54 45 4e 54 22 } //00 00  ;eval "$CONTENT"
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}