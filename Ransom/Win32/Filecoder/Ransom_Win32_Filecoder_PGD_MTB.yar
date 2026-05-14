
rule Ransom_Win32_Filecoder_PGD_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {64 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 6b 69 6c 6c 20 6d 65 3f } //1 do you want to kill me?
		$a_01_1 = {42 69 67 2e 65 78 65 } //1 Big.exe
		$a_01_2 = {59 6f 75 20 61 72 65 20 72 65 61 64 20 74 68 65 20 6d 61 69 6c } //1 You are read the mail
		$a_01_3 = {48 69 2c 20 79 6f 75 20 77 6f 6e } //1 Hi, you won
		$a_01_4 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 75 74 6c 6f 6f 6b } //1 \Software\Microsoft\Outlook
		$a_01_5 = {57 61 72 6e 20 6f 6e 20 4d 61 70 69 20 53 65 6e 64 } //1 Warn on Mapi Send
		$a_01_6 = {57 61 72 20 62 79 20 5b 57 61 72 47 61 6d 65 2c 23 65 6f 66 5d 20 28 20 2a 2a 2a 2a 20 74 69 20 61 6d 6f 20 61 6e 63 68 65 20 73 65 20 74 75 20 6e 6f 6e 20 6d 69 20 72 69 63 61 6d 62 69 20 29 } //1 War by [WarGame,#eof] ( **** ti amo anche se tu non mi ricambi )
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}