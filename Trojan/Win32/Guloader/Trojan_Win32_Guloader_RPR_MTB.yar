
rule Trojan_Win32_Guloader_RPR_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d f0 73 27 8b 45 fc 99 b9 0c 00 00 00 f7 f9 8b 45 ec 0f b6 0c 10 8b 55 f8 03 55 fc 0f b6 02 33 c1 8b 4d f8 03 4d fc 88 01 eb c8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Guloader_RPR_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4c 00 6f 00 6e 00 65 00 79 00 38 00 36 00 5c 00 56 00 61 00 72 00 65 00 6e 00 67 00 61 00 6e 00 } //1 Loney86\Varengan
		$a_01_1 = {46 00 65 00 6a 00 6c 00 73 00 6b 00 75 00 64 00 64 00 65 00 6e 00 65 00 2e 00 4b 00 75 00 6e 00 31 00 32 00 39 00 } //1 Fejlskuddene.Kun129
		$a_01_2 = {4d 00 61 00 61 00 6c 00 65 00 73 00 74 00 6f 00 6b 00 5c 00 46 00 6c 00 79 00 69 00 6e 00 67 00 73 00 2e 00 4f 00 72 00 64 00 } //1 Maalestok\Flyings.Ord
		$a_01_3 = {53 00 65 00 6e 00 67 00 65 00 74 00 70 00 70 00 65 00 74 00 2e 00 4c 00 6f 00 77 00 } //1 Sengetppet.Low
		$a_01_4 = {4f 00 62 00 62 00 65 00 6e 00 69 00 74 00 65 00 2e 00 41 00 64 00 76 00 } //1 Obbenite.Adv
		$a_01_5 = {52 00 61 00 76 00 6e 00 65 00 6d 00 6f 00 64 00 65 00 72 00 65 00 6e 00 73 00 33 00 35 00 2e 00 69 00 6e 00 69 00 } //1 Ravnemoderens35.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win32_Guloader_RPR_MTB_3{
	meta:
		description = "Trojan:Win32/Guloader.RPR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {26 26 26 26 26 26 26 26 26 26 26 66 31 0c 1f d8 cc db e2 eb 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}