
rule TrojanSpy_Win32_Mclip_A_bit{
	meta:
		description = "TrojanSpy:Win32/Mclip.A!bit,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 57 4a 32 61 47 39 7a 64 43 35 6c 65 47 55 3d } //1 TWJ2aG9zdC5leGU=
		$a_01_1 = {63 32 4e 6f 64 47 46 7a 61 33 4d 75 5a 58 68 6c } //1 c2NodGFza3MuZXhl
		$a_01_2 = {4c 32 4e 79 5a 57 46 30 5a 53 41 76 64 47 34 67 58 45 31 70 59 33 4a 76 63 32 39 6d 64 46 78 58 61 57 35 6b 62 33 64 7a 58 45 31 70 59 32 78 70 } //1 L2NyZWF0ZSAvdG4gXE1pY3Jvc29mdFxXaW5kb3dzXE1pY2xp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}