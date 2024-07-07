
rule Ransom_Win32_Genasom_AC{
	meta:
		description = "Ransom:Win32/Genasom.AC,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 65 20 63 6f 64 65 20 64 27 61 63 63 65 73 20 76 6f 75 73 20 70 65 72 6d 65 74 20 64 27 75 74 69 6c 69 73 65 72 20 6e 6f 73 20 63 6f 6e 6e 65 78 69 6f 6e 20 70 72 65 6d 69 75 6d 20 61 66 69 6e 20 64 27 6f 62 74 65 6e 69 72 20 6c 61 20 6d 65 69 6c 6c 65 75 72 65 20 76 69 74 65 73 73 65 20 64 65 20 74 65 6c 65 63 68 61 72 67 65 6d 65 6e 74 20 70 6f 73 73 69 62 6c 65 } //1 Ce code d'acces vous permet d'utiliser nos connexion premium afin d'obtenir la meilleure vitesse de telechargement possible
		$a_01_1 = {68 74 74 70 3a 2f 2f 67 77 2e 6e 65 74 6c 69 6e 6b 69 6e 76 65 73 74 2e 63 6f 6d 2f 63 68 65 63 6b 63 6f 64 65 2e 70 68 70 } //1 http://gw.netlinkinvest.com/checkcode.php
		$a_01_2 = {26 64 6f 63 75 6d 65 6e 74 3d 6f 70 65 6e 6f 66 66 69 63 65 2e 32 30 31 30 2d 66 72 2e } //1 &document=openoffice.2010-fr.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}