
rule Trojan_Win32_OffLoader_AZTA_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.AZTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 12 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 74 72 75 63 6b 6f 62 73 65 72 76 61 74 69 6f 6e 2e 69 63 75 2f 61 61 72 2e 70 68 70 3f } //://truckobservation.icu/aar.php?  10
		$a_80_1 = {3a 2f 2f 6d 69 6e 74 62 6f 72 64 65 72 2e 69 63 75 2f 62 69 65 2e 70 68 70 3f } //://mintborder.icu/bie.php?  10
		$a_80_2 = {3a 2f 2f 70 6f 69 6e 74 72 65 73 70 65 63 74 2e 78 79 7a 2f 68 72 74 2e 70 68 70 3f } //://pointrespect.xyz/hrt.php?  10
		$a_80_3 = {3a 2f 2f 64 6f 67 73 6a 61 72 2e 78 79 7a 2f 68 69 74 2e 70 68 70 3f } //://dogsjar.xyz/hit.php?  10
		$a_80_4 = {3a 2f 2f 73 6b 69 6e 74 65 6d 70 65 72 2e 78 79 7a 2f 62 69 75 2e 70 68 70 3f } //://skintemper.xyz/biu.php?  10
		$a_80_5 = {3a 2f 2f 67 6f 76 65 72 6e 6d 65 6e 74 6d 6f 6e 65 79 2e 69 63 75 2f 67 6c 66 2e 70 68 70 3f } //://governmentmoney.icu/glf.php?  10
		$a_80_6 = {3a 2f 2f 72 6f 62 69 6e 6b 69 73 73 2e 69 6e 66 6f 2f 6b 72 72 2e 70 68 70 3f } //://robinkiss.info/krr.php?  10
		$a_80_7 = {3a 2f 2f 65 76 65 6e 74 61 75 74 68 6f 72 69 74 79 2e 69 6e 66 6f 2f 6b 6b 6b 2e 70 68 70 3f } //://eventauthority.info/kkk.php?  10
		$a_80_8 = {3a 2f 2f 79 65 61 72 64 75 63 6b 73 2e 69 6e 66 6f 2f 79 79 79 2e 70 68 70 3f } //://yearducks.info/yyy.php?  10
		$a_80_9 = {3a 2f 2f 63 72 65 61 6d 70 75 6d 70 2e 69 6e 66 6f 2f 62 6e 6f 2e 70 68 70 3f } //://creampump.info/bno.php?  10
		$a_80_10 = {3a 2f 2f 6e 75 74 6b 69 74 74 65 6e 73 2e 69 6e 66 6f 2f 6b 75 6c 2e 70 68 70 3f } //://nutkittens.info/kul.php?  10
		$a_80_11 = {3a 2f 2f 76 69 73 69 74 6f 72 62 6f 79 2e 69 6e 66 6f 2f 72 74 72 2e 70 68 70 3f } //://visitorboy.info/rtr.php?  10
		$a_80_12 = {3a 2f 2f 70 75 6e 69 73 68 6d 65 6e 74 73 6c 61 76 65 2e 69 6e 66 6f 2f 74 72 65 2e 70 68 70 3f } //://punishmentslave.info/tre.php?  10
		$a_80_13 = {3a 2f 2f 72 6f 6f 66 73 70 61 64 65 2e 69 6e 66 6f 2f 66 6f 75 2e 70 68 70 3f } //://roofspade.info/fou.php?  10
		$a_80_14 = {2f 73 69 6c 65 6e 74 } ///silent  1
		$a_80_15 = {2f 77 65 61 6b 73 65 63 75 72 69 74 79 } ///weaksecurity  1
		$a_80_16 = {2f 6e 6f 63 6f 6f 6b 69 65 73 } ///nocookies  1
		$a_80_17 = {2f 72 65 73 75 6d 65 } ///resume  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*10+(#a_80_4  & 1)*10+(#a_80_5  & 1)*10+(#a_80_6  & 1)*10+(#a_80_7  & 1)*10+(#a_80_8  & 1)*10+(#a_80_9  & 1)*10+(#a_80_10  & 1)*10+(#a_80_11  & 1)*10+(#a_80_12  & 1)*10+(#a_80_13  & 1)*10+(#a_80_14  & 1)*1+(#a_80_15  & 1)*1+(#a_80_16  & 1)*1+(#a_80_17  & 1)*1) >=14
 
}