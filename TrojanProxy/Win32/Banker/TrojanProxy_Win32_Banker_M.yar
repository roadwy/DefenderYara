
rule TrojanProxy_Win32_Banker_M{
	meta:
		description = "TrojanProxy:Win32/Banker.M,SIGNATURE_TYPE_PEHSTR_EXT,ffffffbe 00 ffffffaa 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 73 6c 61 62 6f 6e 69 74 61 2e 62 65 2f 61 66 62 65 65 6c 64 69 6e 67 65 6e 2f 6f 69 2e 70 68 70 23 72 65 66 66 65 72 } //100 islabonita.be/afbeeldingen/oi.php#reffer
		$a_01_1 = {64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f } //50 dropbox.com/u/
		$a_01_2 = {41 75 74 6f 43 6f 6e 66 69 67 55 52 4c 00 45 6e 61 62 6c 65 48 74 74 70 31 5f 31 00 50 72 6f 78 79 45 6e 61 62 6c 65 } //50
		$a_01_3 = {57 69 6e 64 6f 77 73 20 41 70 70 00 53 4f 46 54 57 41 52 45 5c } //20
		$a_01_4 = {2f 37 30 35 37 33 35 30 35 2f 77 69 6e 61 70 70 2e 74 78 74 } //20 /70573505/winapp.txt
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*50+(#a_01_2  & 1)*50+(#a_01_3  & 1)*20+(#a_01_4  & 1)*20) >=170
 
}