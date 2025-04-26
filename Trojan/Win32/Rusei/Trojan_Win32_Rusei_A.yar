
rule Trojan_Win32_Rusei_A{
	meta:
		description = "Trojan:Win32/Rusei.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {7a 7a 7a 73 74 6f 70 69 74 2e 74 78 74 } //1 zzzstopit.txt
		$a_01_1 = {53 65 74 20 7a 7a 7a 73 68 6c 6c 20 3d 20 43 72 65 61 74 65 6f 62 6a 65 63 74 20 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 Set zzzshll = Createobject ("Wscript.Shell")
		$a_01_2 = {7a 7a 7a 73 68 6c 6c 2e 72 65 67 77 72 69 74 65 20 28 22 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 4d 53 20 4f 66 66 69 63 65 22 29 } //1 zzzshll.regwrite ("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MS Office")
		$a_01_3 = {68 74 74 70 3a 2f 2f 78 69 65 73 2e 72 75 2f 3f 69 64 3d 31 } //1 http://xies.ru/?id=1
		$a_01_4 = {68 74 74 70 3a 2f 2f 78 69 65 73 2e 72 75 2f 3f 69 64 3d 33 } //1 http://xies.ru/?id=3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}