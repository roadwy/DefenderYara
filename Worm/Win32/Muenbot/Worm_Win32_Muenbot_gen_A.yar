
rule Worm_Win32_Muenbot_gen_A{
	meta:
		description = "Worm:Win32/Muenbot.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0a 00 08 00 00 "
		
	strings :
		$a_03_0 = {b9 eb 05 00 00 8d 85 90 01 04 e8 90 01 04 6a 00 8b 45 f8 50 8d 85 90 01 04 50 8b 43 20 50 e8 90 01 04 6a 01 e8 90 01 04 8d 85 90 01 04 e8 90 01 04 84 c0 74 ba 90 00 } //5
		$a_03_1 = {3d 37 0c 00 00 7f 2b 0f 84 90 01 02 00 00 2d 8b 00 00 00 74 4d 2d 32 01 00 00 74 5a 2d 63 01 00 00 74 67 2d 99 07 00 00 90 00 } //5
		$a_03_2 = {ba 8b 00 00 00 8b 45 fc e8 90 01 04 8b d8 e9 90 01 04 ba bd 01 00 00 8b 45 fc e8 90 00 } //5
		$a_01_3 = {5b 25 6f 73 25 5d 25 72 63 25 25 72 6e 25 } //1 [%os%]%rc%%rn%
		$a_01_4 = {44 6d 50 61 53 73 57 72 4f 6e 47 } //1 DmPaSsWrOnG
		$a_01_5 = {65 63 68 6f 20 67 65 74 20 75 6e 6e 61 6d 65 64 2e 65 78 65 20 3e 3e 20 62 6c 61 2e 74 78 74 } //1 echo get unnamed.exe >> bla.txt
		$a_01_6 = {56 45 52 53 49 4f 4e 20 2d 75 6e 6e 61 6d 65 64 20 62 6f 74 } //1 VERSION -unnamed bot
		$a_01_7 = {3a 5b 69 4e 46 4f 5d 20 54 72 79 69 6e 67 20 74 6f 20 6d 61 6e 75 61 6c 6c 79 20 72 6f 6f 74 } //1 :[iNFO] Trying to manually root
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=10
 
}