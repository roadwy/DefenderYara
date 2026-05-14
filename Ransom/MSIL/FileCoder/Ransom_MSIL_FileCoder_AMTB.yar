
rule Ransom_MSIL_FileCoder_AMTB{
	meta:
		description = "Ransom:MSIL/FileCoder!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {58 58 58 58 58 58 58 58 58 58 58 58 2e 4d 45 4c 41 4e 43 48 4f 4c 49 41 20 4d 75 73 69 63 20 42 6f 78 20 53 61 64 2c 20 63 72 65 65 70 79 20 73 6f 6e 67 2e 6d 70 33 } //XXXXXXXXXXXX.MELANCHOLIA Music Box Sad, creepy song.mp3  1
		$a_80_1 = {48 65 6c 6c 6f 5f 56 32 2e 54 6f 74 61 6c 42 72 69 63 6b 2b 3c 4e 75 6b 65 45 76 65 72 79 74 68 69 6e 67 3e } //Hello_V2.TotalBrick+<NukeEverything>  1
		$a_80_2 = {58 58 58 58 58 58 58 58 58 58 58 58 2e 58 44 2e 6a 70 67 } //XXXXXXXXXXXX.XD.jpg  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}