
rule TrojanSpy_Win32_Komilet_A_bit{
	meta:
		description = "TrojanSpy:Win32/Komilet.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 42 69 74 63 6f 69 6e 5c 77 61 6c 6c 65 74 73 5c 2a 2e 64 61 74 } //1 \Bitcoin\wallets\*.dat
		$a_01_1 = {43 6f 6f 6b 69 65 73 5c 4b 6f 6d 65 74 61 5f 43 6f 6f 6b 69 65 73 2e 74 78 74 } //1 Cookies\Kometa_Cookies.txt
		$a_01_2 = {25 73 5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 70 72 6f 66 69 6c 65 73 2e 69 6e 69 } //1 %s\Mozilla\Firefox\profiles.ini
		$a_01_3 = {68 74 74 70 3a 2f 2f 31 38 35 2e 32 31 39 2e 38 31 2e 32 33 32 2f 55 70 6c 6f 61 64 2f } //1 http://185.219.81.232/Upload/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}