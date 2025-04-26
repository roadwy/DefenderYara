
rule Ransom_Win32_Genasom_JD{
	meta:
		description = "Ransom:Win32/Genasom.JD,SIGNATURE_TYPE_PEHSTR_EXT,35 00 35 00 0a 00 00 "
		
	strings :
		$a_01_0 = {ff 52 58 6a 00 8b 45 e0 50 8b 4d e0 8b 11 ff 52 60 8b 45 f4 50 8b 4d e0 51 8b 55 e0 8b 02 ff 50 68 8b 4d f8 51 8b 55 e0 52 8b 45 e0 8b 08 ff 51 70 } //50
		$a_01_1 = {44 69 65 20 5a 61 68 6c 75 6e 67 20 70 65 72 20 55 6b 61 73 68 20 62 65 67 6c 65 69 63 68 65 6e } //1 Die Zahlung per Ukash begleichen
		$a_01_2 = {70 6f 72 6e 6f 67 72 61 66 69 73 63 68 65 6e 20 49 6e 68 61 6c 74 65 6e } //1 pornografischen Inhalten
		$a_01_3 = {45 73 20 77 75 72 64 65 6e 20 61 75 63 68 20 45 6d 61 69 6c 73 20 69 6e 20 46 6f 72 6d 20 76 6f 6e 20 53 70 61 6d 2c 6d 69 74 20 74 65 72 72 6f 72 69 73 74 69 73 63 68 65 6e } //1 Es wurden auch Emails in Form von Spam,mit terroristischen
		$a_01_4 = {55 6b 61 73 68 20 64 26 72 73 71 75 6f 3b 75 6e 20 6d 6f 6e 74 61 6e 74 20 64 65 20 31 30 30 20 65 75 72 6f 73 } //1 Ukash d&rsquo;un montant de 100 euros
		$a_01_5 = {64 75 20 63 6f 6e 74 65 6e 75 20 70 6f 72 6e 6f 67 72 61 70 68 69 71 75 65 20 61 69 78 26 65 61 63 75 74 65 3b 73 } //1 du contenu pornographique aix&eacute;s
		$a_01_6 = {64 75 20 53 50 41 4d 20 64 65 20 74 65 6e 64 61 6e 63 65 20 74 65 72 72 6f 72 69 73 74 65 } //1 du SPAM de tendance terroriste
		$a_01_7 = {4d 6f 6e 65 79 50 61 6b 20 6f 66 20 32 30 30 24 } //1 MoneyPak of 200$
		$a_01_8 = {76 69 6f 6c 61 74 69 6e 67 20 43 6f 70 79 72 69 67 68 74 20 61 6e 64 20 52 65 6c 61 74 65 64 20 52 69 67 68 74 73 20 4c 61 77 } //1 violating Copyright and Related Rights Law
		$a_01_9 = {59 6f 75 72 20 50 43 20 69 73 20 62 6c 6f 63 6b 65 64 } //1 Your PC is blocked
	condition:
		((#a_01_0  & 1)*50+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=53
 
}