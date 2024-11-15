
rule Ransom_MSIL_FileCoder_AYG_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.AYG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {78 6d 62 2e 70 79 74 68 6f 6e 61 6e 79 77 68 65 72 65 2e 63 6f 6d } //2 xmb.pythonanywhere.com
		$a_01_1 = {59 6f 75 20 62 65 63 61 6d 65 20 76 69 63 74 69 6d 20 6f 66 20 74 68 65 20 72 61 7a 72 75 73 68 65 6e 69 79 65 20 72 61 6e 73 6f 6d 77 61 72 65 21 } //1 You became victim of the razrusheniye ransomware!
		$a_01_2 = {49 66 20 79 6f 75 20 72 65 70 6f 72 74 20 75 73 20 41 46 54 45 52 20 72 65 73 74 6f 72 61 74 69 6f 6e 2c 20 77 65 20 57 49 4c 4c 20 61 74 74 61 63 6b 20 79 6f 75 20 61 67 61 69 6e 21 21 21 } //1 If you report us AFTER restoration, we WILL attack you again!!!
		$a_01_3 = {25 73 2e 72 61 7a } //1 %s.raz
		$a_01_4 = {41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 } //1 AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}