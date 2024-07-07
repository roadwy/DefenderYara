
rule Trojan_Win32_Niner_A{
	meta:
		description = "Trojan:Win32/Niner.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {7b 36 38 45 46 39 38 44 45 2d 39 44 34 46 2d 34 38 39 41 2d 41 31 31 46 2d 39 36 33 43 30 41 31 37 30 33 38 36 7d 20 3d 20 73 20 27 41 75 74 6f 27 } //1 {68EF98DE-9D4F-489A-A11F-963C0A170386} = s 'Auto'
		$a_01_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 39 75 2e 69 6e 69 } //1 C:\WINDOWS\9u.ini
		$a_01_2 = {75 72 6c 2e 69 6e 69 } //1 url.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}