
rule TrojanProxy_Win32_Bankorde_A{
	meta:
		description = "TrojanProxy:Win32/Bankorde.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {42 69 74 74 65 20 67 65 62 65 6e 20 53 69 65 20 64 61 73 20 50 61 73 73 77 6f 72 74 20 65 69 6e } //1 Bitte geben Sie das Passwort ein
		$a_01_1 = {2d 72 20 2d 61 20 2d 73 20 2d 68 20 25 57 69 6e 64 69 72 25 5c 73 79 73 74 45 6d 33 32 5c 64 72 69 76 45 72 73 5c 45 74 63 5c 68 6f 73 74 73 } //1 -r -a -s -h %Windir%\systEm32\drivErs\Etc\hosts
		$a_01_2 = {5c 45 74 63 5c 68 6f 73 74 73 0d 0a 45 63 68 6f 20 } //1
		$a_01_3 = {42 61 4e 4b 49 6e 67 2e 6e 6f 6e 67 68 79 75 70 2e 63 6f 6d 3e 3e 63 3a 2f } //1 BaNKIng.nonghyup.com>>c:/
		$a_01_4 = {42 61 4e 4b 49 6e 67 2e 53 48 49 4e 48 41 4e 2e 63 6f 6d 3e 3e 63 3a 2f } //1 BaNKIng.SHINHAN.com>>c:/
		$a_01_5 = {6d 79 42 61 4e 4b 2e 49 42 4b 2e 63 6f 2e 6b 72 3e 3e 63 3a 2f } //1 myBaNK.IBK.co.kr>>c:/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}