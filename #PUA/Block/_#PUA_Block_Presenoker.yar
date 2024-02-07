
rule _#PUA_Block_Presenoker{
	meta:
		description = "!#PUA:Block:Presenoker,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 61 00 67 00 7a 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2e 00 70 00 77 00 } //01 00  htagzdownload.pw
		$a_01_1 = {73 00 70 00 61 00 63 00 65 00 31 00 2e 00 61 00 64 00 6d 00 69 00 6e 00 70 00 72 00 65 00 73 00 73 00 75 00 72 00 65 00 2e 00 73 00 70 00 61 00 63 00 65 00 } //00 00  space1.adminpressure.space
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_Presenoker_2{
	meta:
		description = "!#PUA:Block:Presenoker,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 61 64 70 6c 75 73 2e 63 68 6c 62 69 7a 2e 63 6f 6d 2f 61 64 70 6c 75 73 2d 61 70 69 } //01 00  http://adplus.chlbiz.com/adplus-api
		$a_01_1 = {68 74 74 70 3a 2f 2f 70 64 61 70 69 2e 7a 6e 79 73 68 75 72 75 66 61 2e 63 6f 6d 2f 63 69 74 79 } //01 00  http://pdapi.znyshurufa.com/city
		$a_01_2 = {46 00 49 00 44 00 44 00 4c 00 45 00 52 00 } //01 00  FIDDLER
		$a_01_3 = {57 00 49 00 52 00 45 00 53 00 48 00 41 00 52 00 4b 00 } //00 00  WIRESHARK
	condition:
		any of ($a_*)
 
}
rule _#PUA_Block_Presenoker_3{
	meta:
		description = "!#PUA:Block:Presenoker,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 64 20 77 69 74 68 20 47 49 4d 50 } //01 00  Created with GIMP
		$a_01_1 = {47 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 67 6c 65 2e 55 73 65 72 43 6f 6e 74 72 6f 6c 31 } //01 00  Goooooooooogle.UserControl1
		$a_01_2 = {52 00 45 00 47 00 20 00 41 00 44 00 44 00 20 00 48 00 4b 00 43 00 55 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 54 00 52 00 32 00 20 00 2f 00 76 00 20 00 75 00 6e 00 69 00 20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 53 00 5a 00 20 00 2f 00 64 00 20 00 31 00 } //01 00  REG ADD HKCU\Software\TR2 /v uni /t REG_SZ /d 1
		$a_01_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 76 00 69 00 64 00 65 00 6f 00 63 00 6f 00 64 00 65 00 63 00 78 00 76 00 69 00 64 00 2e 00 63 00 6f 00 6d 00 2f 00 74 00 72 00 61 00 63 00 6b 00 2f 00 64 00 69 00 73 00 70 00 6c 00 61 00 79 00 2e 00 70 00 68 00 70 00 } //00 00  http://videocodecxvid.com/track/display.php
	condition:
		any of ($a_*)
 
}