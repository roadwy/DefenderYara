
rule Trojan_Win32_Klovbot_D{
	meta:
		description = "Trojan:Win32/Klovbot.D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 52 00 4f 00 42 00 45 00 52 00 54 00 4f 00 2e 00 76 00 62 00 70 00 00 00 } //1
		$a_01_1 = {73 00 65 00 72 00 76 00 65 00 72 00 3d 00 52 00 4f 00 42 00 49 00 4e 00 53 00 4f 00 4e 00 3b 00 75 00 69 00 64 00 3d 00 52 00 4f 00 42 00 49 00 4e 00 53 00 4f 00 4e 00 3b 00 70 00 77 00 64 00 3d 00 52 00 4f 00 42 00 49 00 4e 00 53 00 4f 00 4e 00 3b 00 64 00 61 00 74 00 61 00 62 00 61 00 73 00 65 00 3d 00 52 00 4f 00 42 00 49 00 4e 00 53 00 4f 00 4e 00 } //1 server=ROBINSON;uid=ROBINSON;pwd=ROBINSON;database=ROBINSON
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}