
rule Ransom_Win64_FileCoder_C_AMTB{
	meta:
		description = "Ransom:Win64/FileCoder.C!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_80_0 = {49 46 20 59 4f 55 20 44 4f 20 4e 4f 54 20 54 41 4b 45 20 43 41 52 45 20 4f 46 20 54 48 49 53 20 49 53 53 55 45 20 57 49 54 48 49 4e 20 54 48 45 20 4e 45 58 54 20 37 32 20 48 4f 55 52 53 2c 20 59 4f 55 20 57 49 4c 4c 20 46 41 43 45 20 44 4f 55 42 4c 45 20 50 52 49 43 45 20 49 4e 43 52 45 41 53 45 2e } //IF YOU DO NOT TAKE CARE OF THIS ISSUE WITHIN THE NEXT 72 HOURS, YOU WILL FACE DOUBLE PRICE INCREASE.  1
		$a_80_1 = {42 65 66 6f 72 65 20 70 61 79 69 6e 67 20 79 6f 75 20 63 61 6e 20 73 65 6e 64 20 32 2d 33 20 66 69 6c 65 73 20 6c 65 73 73 20 74 68 61 6e 20 31 4d 42 2c 20 77 65 20 77 69 6c 6c 20 64 65 63 72 79 70 74 20 74 68 65 6d 20 74 6f 20 67 75 61 72 61 6e 74 65 65 2e } //Before paying you can send 2-3 files less than 1MB, we will decrypt them to guarantee.  1
		$a_80_2 = {45 6e 63 72 79 70 74 2e 48 69 67 68 65 72 54 68 61 6e 35 30 30 4d 42 } //Encrypt.HigherThan500MB  2
		$a_80_3 = {53 70 65 63 69 61 6c 20 46 69 6c 65 73 2e 45 6e 63 72 79 70 74 53 70 65 63 69 61 6c 46 69 6c 65 73 46 75 72 74 68 65 72 } //Special Files.EncryptSpecialFilesFurther  2
		$a_80_4 = {57 61 6c 6c 70 61 70 65 72 2e 43 68 61 6e 67 65 44 65 73 6b 74 6f 70 57 61 6c 6c 70 61 70 65 72 } //Wallpaper.ChangeDesktopWallpaper  2
		$a_80_5 = {4c 6f 67 2e 44 69 73 63 6f 72 64 4c 6f 67 4d 65 73 73 61 67 65 } //Log.DiscordLogMessage  2
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2) >=7
 
}