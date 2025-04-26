
rule Worm_Win32_Combra_G{
	meta:
		description = "Worm:Win32/Combra.G,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //5 SOFTWARE\Borland\Delphi
		$a_01_1 = {6d 75 73 69 63 61 73 2f 6d 70 33 22 } //1 musicas/mp3"
		$a_01_2 = {61 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 69 6e 74 65 72 6e 65 74 20 65 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 20 68 74 74 70 3a } //1 arquivos de programas\internet explorer\iexplore.exe http:
		$a_01_3 = {74 65 72 72 61 2e 63 6f 6d 2e 62 72 } //1 terra.com.br
		$a_01_4 = {23 33 33 33 33 39 39 22 3e 3c 62 3e 43 6c 69 71 75 65 } //1 #333399"><b>Clique
		$a_01_5 = {3c 2f 74 72 3e 3c 2f 74 61 62 6c 65 3e } //1 </tr></table>
		$a_00_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_00_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1) >=10
 
}