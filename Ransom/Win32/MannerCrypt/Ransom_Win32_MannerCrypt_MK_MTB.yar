
rule Ransom_Win32_MannerCrypt_MK_MTB{
	meta:
		description = "Ransom:Win32/MannerCrypt.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 51 51 4d 75 73 69 63 4d 6f 64 65 6c 5c 76 63 72 75 6e 74 69 6d 65 31 34 30 5c 52 65 6c 65 61 73 65 5c 76 63 72 75 6e 74 69 6d 65 31 34 30 2e 70 64 62 } //1 \QQMusicModel\vcruntime140\Release\vcruntime140.pdb
		$a_01_1 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 6d 65 21 } //1 All your files are encrypted by me!
		$a_01_2 = {50 6c 65 61 73 65 20 70 61 79 20 61 20 72 61 6e 73 6f 6d 20 6f 66 20 31 30 30 55 53 44 54 20 74 6f 20 6d 65 21 } //1 Please pay a ransom of 100USDT to me!
		$a_01_3 = {4f 74 68 65 72 77 69 73 65 2c 20 79 6f 75 72 20 66 69 6c 65 73 20 63 61 6e 6e 6f 74 20 62 65 20 64 65 63 72 79 70 74 65 64 20 65 76 65 6e 20 69 66 20 47 6f 64 20 63 6f 6d 65 73 } //1 Otherwise, your files cannot be decrypted even if God comes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}