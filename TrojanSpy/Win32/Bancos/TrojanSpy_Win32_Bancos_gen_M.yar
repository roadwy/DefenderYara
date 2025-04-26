
rule TrojanSpy_Win32_Bancos_gen_M{
	meta:
		description = "TrojanSpy:Win32/Bancos.gen!M,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 0e 00 00 "
		
	strings :
		$a_01_0 = {49 4c 66 34 44 34 62 6e 48 74 39 34 44 70 61 75 48 37 31 42 54 61 57 72 50 61 39 49 53 4d 50 6e 48 34 72 67 49 61 7a 44 4f 63 76 39 53 74 34 } //1 ILf4D4bnHt94DpauH71BTaWrPa9ISMPnH4rgIazDOcv9St4
		$a_01_1 = {49 5a 44 34 49 71 47 72 44 37 39 38 44 70 4b 76 48 35 66 42 52 71 66 71 44 4d 6a 4a 4f 4d 62 6e 49 } //1 IZD4IqGrD798DpKvH5fBRqfqDMjJOMbnI
		$a_01_2 = {4a 33 44 4b 44 35 34 72 48 37 35 39 44 5a 4b 6f 4a 74 35 6b 53 61 69 71 } //1 J3DKD54rH759DZKoJt5kSaiq
		$a_01_3 = {4c 33 54 34 51 35 44 71 49 36 35 32 4f 71 6e 72 4b 34 } //1 L3T4Q5DqI652OqnrK4
		$a_01_4 = {54 37 44 68 53 74 48 61 42 63 4c 75 } //1 T7DhStHaBcLu
		$a_01_5 = {49 4b 6a 67 52 71 4b 71 49 36 7a 35 4a 35 58 43 4a 74 48 47 45 34 66 71 49 34 54 35 44 36 39 51 48 34 6a 73 49 61 7a 44 45 4b 7a 42 53 71 } //1 IKjgRqKqI6z5J5XCJtHGE4fqI4T5D69QH4jsIazDEKzBSq
		$a_01_6 = {49 4b 6a 6f 45 34 48 6f 45 4c 58 4c 4f 74 50 38 4a 74 48 47 45 34 62 5a 44 4b 76 4a 4f 4d 39 4f 4b } //1 IKjoE4HoELXLOtP8JtHGE4bZDKvJOM9OK
		$a_01_7 = {49 4b 72 38 44 72 39 58 55 63 76 48 4f 74 50 38 49 63 35 4e 53 61 62 58 53 } //1 IKr8Dr9XUcvHOtP8Ic5NSabXS
		$a_01_8 = {49 4d 48 37 52 61 7a 6e 51 63 76 48 4a 61 57 72 49 61 72 73 44 71 6d 70 } //1 IMH7RaznQcvHJaWrIarsDqmp
		$a_01_9 = {49 64 47 6e 4f 71 6a 6e 51 4e 48 35 4a 4d 76 37 4c 33 44 } //1 IdGnOqjnQNH5JMv7L3D
		$a_01_10 = {4a 74 31 63 4b 71 69 74 45 4d 6e 47 54 33 62 4f 4b } //1 Jt1cKqitEMnGT3bOK
		$a_01_11 = {4f 70 66 53 4b 37 39 6c 50 74 39 58 52 4b 48 } //1 OpfSK79lPt9XRKH
		$a_01_12 = {4f 70 66 53 47 4e 39 6e 54 4d 62 73 52 6f 31 61 50 49 31 6d 53 63 7a 64 53 63 35 6a 4f 4e 44 53 } //1 OpfSGN9nTMbsRo1aPI1mSczdSc5jONDS
		$a_01_13 = {4b 71 7a 36 4c 35 54 31 4b 61 4c 53 4a 4b 62 33 4b 61 7a 4a 4a 71 50 4b 4e 35 54 39 4a 61 48 46 4c 72 44 53 47 72 4c 49 4b 61 4c 45 4c 35 50 35 4b 62 44 39 4a 71 76 53 4b 62 4c 45 } //1 Kqz6L5T1KaLSJKb3KazJJqPKN5T9JaHFLrDSGrLIKaLEL5P5KbD9JqvSKbLE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=2
 
}