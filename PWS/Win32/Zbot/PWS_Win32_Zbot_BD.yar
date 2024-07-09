
rule PWS_Win32_Zbot_BD{
	meta:
		description = "PWS:Win32/Zbot.BD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 00 83 44 24 ?? 01 c1 6c 24 ?? 02 c1 6c 24 ?? 02 c1 6c 24 ?? 02 c1 6c 24 ?? 02 83 44 24 ?? 01 83 7c 24 ?? 04 75 10 } //1
		$a_00_1 = {48 65 6c 6c 6f 20 6d 79 20 66 72 69 65 6e 64 73 20 66 72 6f 6d 20 41 76 69 72 61 21 20 59 6f 75 72 20 74 6f 70 69 63 20 22 48 61 72 64 20 74 69 6d 65 73 20 66 6f 72 20 68 61 63 6b 65 72 73 22 20 69 73 20 61 20 76 65 72 79 20 73 74 75 70 69 64 20 74 65 78 74 20 66 6f 72 20 73 74 75 70 69 64 20 6c 61 6d 65 72 73 } //1 Hello my friends from Avira! Your topic "Hard times for hackers" is a very stupid text for stupid lamers
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}