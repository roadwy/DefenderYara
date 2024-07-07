
rule Trojan_Win32_Azorult_A{
	meta:
		description = "Trojan:Win32/Azorult.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_01_0 = {67 69 67 6f 72 65 72 69 76 65 6b 65 6b 61 72 69 20 73 61 72 75 67 69 6e 69 6c 65 76 75 73 75 62 6f 6e 61 78 69 77 69 20 79 6f 76 69 7a 69 } //1 gigorerivekekari saruginilevusubonaxiwi yovizi
		$a_01_1 = {6e 75 6b 69 73 69 68 69 6e 69 2e 74 78 74 } //1 nukisihini.txt
		$a_01_2 = {62 65 70 75 68 75 67 75 77 75 6a 65 6a 69 78 61 66 75 70 61 63 65 6c 75 6e 75 2e 6a 70 67 } //1 bepuhuguwujejixafupacelunu.jpg
		$a_01_3 = {79 69 66 75 6e 6f 67 61 63 65 62 6f 72 61 63 6f 79 65 2e 74 78 74 } //1 yifunogaceboracoye.txt
		$a_01_4 = {6b 75 6c 75 79 65 73 65 70 75 68 65 20 7a 69 6d 6f 73 61 66 6f 64 69 20 64 75 73 65 70 65 6a 61 63 75 64 61 67 65 6d 75 76 61 66 61 6c 6f 6d 69 } //1 kuluyesepuhe zimosafodi dusepejacudagemuvafalomi
		$a_01_5 = {73 65 79 69 63 75 77 61 74 69 74 61 2e 74 78 74 } //1 seyicuwatita.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=2
 
}