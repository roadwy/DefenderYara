
rule Trojan_Win32_Guloader_CM_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0a 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 69 6e 64 62 79 67 67 65 72 61 6e 74 61 6c 5c 6b 61 6d 6d 79 } //1 Software\indbyggerantal\kammy
		$a_01_1 = {62 72 61 6b 74 75 64 73 5c 73 74 72 61 70 6e 69 6e 67 2e 69 6e 69 } //1 braktuds\strapning.ini
		$a_01_2 = {70 6f 6c 65 6d 69 63 69 73 65 73 25 5c 69 6e 74 65 72 63 72 79 73 74 61 6c 6c 69 73 65 73 5c 68 6f 6c 6f 70 72 6f 74 65 69 64 65 2e 70 6f 73 } //1 polemicises%\intercrystallises\holoproteide.pos
		$a_01_3 = {48 6f 6c 6c 79 77 6f 6f 64 73 6b 75 65 73 70 69 6c 6c 65 72 5c 6b 6f 72 72 65 73 70 6f 6e 64 65 72 65 64 65 73 2e 69 6e 69 } //1 Hollywoodskuespiller\korresponderedes.ini
		$a_01_4 = {62 65 64 72 65 76 69 64 65 6e 5c 73 61 6e 64 61 73 74 72 61 2e 73 75 6c } //1 bedreviden\sandastra.sul
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 69 6e 64 73 6b 79 64 6e 69 6e 67 65 72 5c 61 70 6f 6b 72 79 66 65 6e } //1 Software\indskydninger\apokryfen
		$a_01_6 = {53 6c 61 64 64 65 72 74 61 73 6b 65 72 31 37 36 2e 72 6f 6d } //1 Sladdertasker176.rom
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 62 73 73 65 73 6b 75 64 73 5c 55 6e 69 6e 73 74 61 6c 6c 5c 50 61 61 68 61 65 66 74 6e 69 6e 67 65 6e 5c 69 64 72 74 73 6b 6c 75 62 } //1 Software\Microsoft\Windows\bsseskuds\Uninstall\Paahaeftningen\idrtsklub
		$a_01_8 = {53 6f 66 74 77 61 72 65 5c 72 61 61 64 76 69 6c 64 65 73 5c 75 64 66 72 73 65 6c 73 66 6f 72 62 75 64 64 65 6e 65 73 } //1 Software\raadvildes\udfrselsforbuddenes
		$a_01_9 = {4c 6f 6e 67 68 65 61 64 73 25 5c 74 65 6b 73 74 74 79 70 65 72 6e 65 73 2e 70 61 72 } //1 Longheads%\teksttypernes.par
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=5
 
}