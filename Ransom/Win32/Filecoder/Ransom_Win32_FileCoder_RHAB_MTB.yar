
rule Ransom_Win32_FileCoder_RHAB_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.RHAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_03_0 = {50 45 00 00 4c 01 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 0e 27 00 fe 01 00 00 f0 63 00 00 00 00 00 67 13 } //2
		$a_00_1 = {49 00 66 00 20 00 6e 00 6f 00 74 00 2c 00 20 00 79 00 6f 00 75 00 20 00 63 00 61 00 6e 00 27 00 74 00 20 00 72 00 65 00 63 00 6f 00 76 00 65 00 72 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 66 00 6f 00 72 00 65 00 76 00 65 00 72 00 } //3 If not, you can't recover your files forever
		$a_00_2 = {49 00 73 00 20 00 74 00 68 00 69 00 73 00 20 00 72 00 69 00 67 00 68 00 74 00 20 00 6b 00 65 00 79 00 } //1 Is this right key
		$a_00_3 = {57 00 61 00 6c 00 6c 00 70 00 61 00 70 00 65 00 72 00 20 00 73 00 65 00 74 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6c 00 6c 00 79 00 } //1 Wallpaper set successfully
		$a_01_4 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 6f 75 72 20 49 6e 76 69 73 69 62 6c 65 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 All your files have been encrypted by our Invisible Ransomware
		$a_00_5 = {43 00 6f 00 70 00 79 00 20 00 4d 00 79 00 20 00 42 00 54 00 43 00 20 00 41 00 64 00 64 00 72 00 65 00 73 00 73 00 } //1 Copy My BTC Address
		$a_00_6 = {43 00 6f 00 70 00 79 00 20 00 4d 00 79 00 20 00 55 00 53 00 44 00 54 00 20 00 54 00 52 00 43 00 32 00 30 00 } //1 Copy My USDT TRC20
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*3+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=10
 
}