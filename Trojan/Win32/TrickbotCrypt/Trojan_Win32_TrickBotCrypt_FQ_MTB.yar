
rule Trojan_Win32_TrickBotCrypt_FQ_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 4d f8 03 0d 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 0f af 15 90 01 04 03 ca 2b 0d 90 01 04 2b 0d 90 01 04 8b 55 0c 8b 75 08 8a 04 02 32 04 0e 8b 4d ec 03 0d 90 01 04 03 0d 90 01 04 2b 0d 90 01 04 2b 0d 90 01 04 03 0d 90 01 04 8b 55 0c 88 04 0a e9 90 00 } //0a 00 
		$a_81_1 = {44 57 61 47 24 7a 40 46 47 29 6a 29 58 6e 30 36 4c 7a 29 42 25 6d 4a 74 72 43 5e 2a 28 79 5f 49 2a 76 2a 45 24 31 59 4b 29 43 44 5a 46 34 67 21 49 49 6b 32 55 72 49 25 72 2b 63 38 54 48 77 66 3f 42 6f 76 72 74 6c 64 56 4e 62 31 } //0a 00  DWaG$z@FG)j)Xn06Lz)B%mJtrC^*(y_I*v*E$1YK)CDZF4g!IIk2UrI%r+c8THwf?BovrtldVNb1
		$a_81_2 = {31 66 4e 68 61 34 6b 36 74 33 63 79 61 24 39 45 52 23 35 37 5e 72 28 4d 53 57 72 62 36 6f 54 77 42 78 4b 26 6d 63 34 38 3e 43 4b 36 78 53 6f 28 61 7a 37 3f 37 3c 2a 46 23 2b 40 4b 50 32 62 23 48 55 69 24 55 57 25 30 23 50 23 3f 3f 6d 45 61 67 28 4c 31 4e 65 38 68 68 77 66 51 70 4e 23 67 26 } //00 00  1fNha4k6t3cya$9ER#57^r(MSWrb6oTwBxK&mc48>CK6xSo(az7?7<*F#+@KP2b#HUi$UW%0#P#??mEag(L1Ne8hhwfQpN#g&
	condition:
		any of ($a_*)
 
}