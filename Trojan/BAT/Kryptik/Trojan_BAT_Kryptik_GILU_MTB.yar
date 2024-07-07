
rule Trojan_BAT_Kryptik_GILU_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.GILU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 0c 00 00 "
		
	strings :
		$a_01_0 = {24 62 35 30 64 33 66 63 39 2d 64 64 34 38 2d 34 38 65 64 2d 61 33 31 66 2d 64 31 37 61 33 39 33 34 34 30 32 38 } //10 $b50d3fc9-dd48-48ed-a31f-d17a39344028
		$a_01_1 = {41 64 64 43 42 53 5f 56 61 6c 75 65 73 } //1 AddCBS_Values
		$a_01_2 = {46 4c 75 78 43 65 6e 74 65 72 } //1 FLuxCenter
		$a_01_3 = {42 53 54 52 4d 61 72 73 68 61 6c 65 72 } //1 BSTRMarshaler
		$a_01_4 = {4f 62 6a 65 63 74 49 64 65 6e 74 69 66 69 65 72 } //1 ObjectIdentifier
		$a_01_5 = {63 72 65 61 74 65 53 71 75 61 72 65 73 } //1 createSquares
		$a_01_6 = {6e 65 77 47 61 6d 65 42 75 74 74 6f 6e 5f 43 6c 69 63 6b } //1 newGameButton_Click
		$a_01_7 = {73 71 75 61 72 65 73 4b 65 79 } //1 squaresKey
		$a_01_8 = {75 70 64 61 74 65 42 6f 61 72 64 } //1 updateBoard
		$a_01_9 = {4f 62 6a 65 63 74 48 6f 6c 64 65 72 4c 69 73 74 47 61 6d 65 5f 4b 65 79 44 6f 77 6e } //1 ObjectHolderListGame_KeyDown
		$a_01_10 = {4f 62 6a 65 63 74 48 6f 6c 64 65 72 4c 69 73 74 47 61 6d 65 5f 4b 65 79 50 72 65 73 73 } //1 ObjectHolderListGame_KeyPress
		$a_01_11 = {4f 62 6a 65 63 74 48 6f 6c 64 65 72 4c 69 73 74 47 61 6d 65 5f 4b 65 79 55 70 } //1 ObjectHolderListGame_KeyUp
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=21
 
}