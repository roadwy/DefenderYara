
rule Ransom_Win64_Goransom_MKZ_MTB{
	meta:
		description = "Ransom:Win64/Goransom.MKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 09 00 00 "
		
	strings :
		$a_81_0 = {6e 44 65 35 2d 41 30 43 65 33 45 79 51 7a 58 4b 4c 64 48 33 2f 56 71 76 6c 30 56 34 34 6c 77 2d 4a 54 34 64 35 49 4d 79 4f 2f 52 57 47 74 37 6c 54 34 4d 68 42 6d 45 52 69 30 48 46 61 78 2f 73 46 4a 79 30 39 75 69 48 58 77 44 59 73 41 4d 4f 61 41 6d } //1 nDe5-A0Ce3EyQzXKLdH3/Vqvl0V44lw-JT4d5IMyO/RWGt7lT4MhBmERi0HFax/sFJy09uiHXwDYsAMOaAm
		$a_81_1 = {63 69 70 68 65 72 2e 63 62 63 45 6e 63 72 79 70 74 65 72 } //5 cipher.cbcEncrypter
		$a_81_2 = {61 65 73 2e 65 6e 63 72 79 70 74 42 6c 6f 63 6b 47 6f } //5 aes.encryptBlockGo
		$a_81_3 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 46 69 6c 65 } //1 main.encryptFile
		$a_81_4 = {47 6f 72 61 6e 73 6f 6d 2f 65 6e 63 72 79 70 74 2e 67 6f } //5 Goransom/encrypt.go
		$a_81_5 = {50 72 69 76 61 74 65 4b 65 79 } //1 PrivateKey
		$a_81_6 = {61 73 20 20 61 74 20 20 66 70 3d 20 69 73 20 20 6c 72 3a 20 6f 66 20 20 6f 6e 20 20 70 63 } //1 as  at  fp= is  lr: of  on  pc
		$a_81_7 = {30 33 33 30 2b 30 34 33 30 2b 30 35 33 30 2b 30 35 34 35 2b 30 36 33 30 2b 30 38 34 35 2b 31 30 33 30 2b 31 32 34 35 2b 31 33 34 35 2c 20 2e 2e 2e 2c 20 66 70 } //1 0330+0430+0530+0545+0630+0845+1030+1245+1345, ..., fp
		$a_81_8 = {2d 49 6e 66 2e 62 61 74 2e 63 6d 64 2e 63 6f 6d 2e 63 73 73 2e 65 78 65 2e 67 69 66 2e 68 74 6d 2e 6a 70 67 2e 6d 6a 73 2e 70 64 66 2e 70 6e 67 } //1 -Inf.bat.cmd.com.css.exe.gif.htm.jpg.mjs.pdf.png
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*5+(#a_81_2  & 1)*5+(#a_81_3  & 1)*1+(#a_81_4  & 1)*5+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=21
 
}