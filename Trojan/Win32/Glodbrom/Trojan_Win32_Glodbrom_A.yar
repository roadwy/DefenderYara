
rule Trojan_Win32_Glodbrom_A{
	meta:
		description = "Trojan:Win32/Glodbrom.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {6e 65 74 73 68 20 77 6c 61 6e 20 73 68 6f 77 20 70 72 6f 66 69 6c 65 73 20 3e 3e 20 6f 68 61 67 69 2e 74 78 74 } //2 netsh wlan show profiles >> ohagi.txt
		$a_01_1 = {64 65 6c 20 63 6f 6e 61 6e 2e 62 6d 70 00 31 00 55 53 45 52 4e 41 4d 45 00 32 00 33 00 61 2c } //2
		$a_01_2 = {6f 68 61 67 69 2e 74 78 74 } //1 ohagi.txt
		$a_01_3 = {65 63 68 6f 20 41 4e 4e 49 45 2d 44 41 45 4d 4f 4e } //1 echo ANNIE-DAEMON
		$a_01_4 = {69 70 63 6f 6e 66 69 67 20 2f 61 6c 6c 20 3e 3e 20 6f 68 61 67 69 2e 74 78 74 20 32 } //1 ipconfig /all >> ohagi.txt 2
		$a_01_5 = {43 6f 6b 6b 69 65 3a 20 78 74 6c 5f 73 3d 25 73 } //1 Cokkie: xtl_s=%s
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}