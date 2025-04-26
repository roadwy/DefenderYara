
rule Trojan_Win32_EmotetCrypt_RR_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {6b 71 6a 67 68 76 70 73 67 63 6d 6a 79 2e 64 6c 6c } //1 kqjghvpsgcmjy.dll
		$a_01_1 = {43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c } //1 Control_RunDLL
		$a_01_2 = {62 65 6f 6b 7a 78 75 61 6e 63 61 73 78 75 74 75 6f } //1 beokzxuancasxutuo
		$a_01_3 = {65 77 70 76 70 72 65 67 69 6c 63 7a 78 6c 6e } //1 ewpvpregilczxln
		$a_01_4 = {65 78 78 71 6b 67 63 79 64 6b 79 7a 72 6a 72 71 64 } //1 exxqkgcydkyzrjrqd
		$a_01_5 = {66 64 73 79 79 7a 75 68 79 67 } //1 fdsyyzuhyg
		$a_01_6 = {67 67 6e 6b 6b 75 63 } //1 ggnkkuc
		$a_01_7 = {70 73 78 6f 72 62 6a 6e 62 79 70 6e } //1 psxorbjnbypn
		$a_01_8 = {75 73 7a 79 6f 6e 65 62 75 70 7a 67 63 68 78 76 } //1 uszyonebupzgchxv
		$a_01_9 = {76 6b 6f 6c 7a 78 78 77 71 66 6a } //1 vkolzxxwqfj
		$a_01_10 = {77 6b 66 66 6c 76 66 6d 71 61 } //1 wkfflvfmqa
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}