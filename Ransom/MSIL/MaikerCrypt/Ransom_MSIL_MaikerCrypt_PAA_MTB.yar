
rule Ransom_MSIL_MaikerCrypt_PAA_MTB{
	meta:
		description = "Ransom:MSIL/MaikerCrypt.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {2e 00 61 00 65 00 73 00 } //1 .aes
		$a_01_1 = {43 72 79 70 74 4d 61 69 6b 65 72 } //1 CryptMaiker
		$a_01_2 = {65 00 71 00 77 00 63 00 7a 00 73 00 65 00 77 00 63 00 78 00 7a 00 71 00 77 00 65 00 71 00 77 00 65 00 } //1 eqwczsewcxzqweqwe
		$a_01_3 = {53 79 73 74 65 6d 2e 57 69 6e 64 6f 77 73 2e 4d 61 72 6b 75 70 } //1 System.Windows.Markup
		$a_01_4 = {52 4e 47 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 RNGCryptoServiceProvider
		$a_01_5 = {2f 00 4e 00 6f 00 4e 00 61 00 6d 00 65 00 3b 00 63 00 6f 00 6d 00 70 00 6f 00 6e 00 65 00 6e 00 74 00 2f 00 6d 00 61 00 69 00 6e 00 77 00 69 00 6e 00 64 00 6f 00 77 00 2e 00 78 00 61 00 6d 00 6c 00 } //1 /NoName;component/mainwindow.xaml
		$a_01_6 = {4e 6f 4e 61 6d 65 5c 4e 6f 4e 61 6d 65 5c 6f 62 6a 5c 44 65 62 75 67 5c 4e 6f 4e 61 6d 65 2e 70 64 62 } //1 NoName\NoName\obj\Debug\NoName.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}