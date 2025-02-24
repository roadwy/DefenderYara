
rule Trojan_Win32_Guloader_CZ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_01_0 = {6e 61 72 72 6f 77 6e 65 73 73 2e 69 6e 69 } //2 narrowness.ini
		$a_01_1 = {62 65 66 6f 6c 6b 6e 69 6e 67 73 67 72 75 70 70 65 72 5c 6d 6f 72 61 73 2e 7a 6f 6e } //2 befolkningsgrupper\moras.zon
		$a_01_2 = {48 79 6c 64 65 62 72 72 65 74 32 2e 66 61 6a } //1 Hyldebrret2.faj
		$a_01_3 = {70 65 6c 76 65 74 69 61 2e 74 78 74 } //1 pelvetia.txt
		$a_01_4 = {73 61 6b 6b 65 6e 64 65 2e 64 72 6f } //1 sakkende.dro
		$a_01_5 = {41 66 74 72 6b 6b 65 73 5c 72 61 6d 73 68 6f 72 6e 5c 6c 61 63 68 72 79 6d 61 65 66 6f 72 6d } //1 Aftrkkes\ramshorn\lachrymaeform
		$a_01_6 = {47 6c 79 70 68 6f 67 72 61 70 68 5c 4d 61 6c 76 61 63 65 61 65 35 36 5c 61 6c 74 72 75 69 73 74 65 6e } //1 Glyphograph\Malvaceae56\altruisten
		$a_01_7 = {65 6e 65 72 67 69 75 64 66 6f 6c 64 65 6c 73 65 72 73 2e 55 6b 75 } //1 energiudfoldelsers.Uku
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=10
 
}