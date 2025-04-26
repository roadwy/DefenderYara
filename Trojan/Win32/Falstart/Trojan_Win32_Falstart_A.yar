
rule Trojan_Win32_Falstart_A{
	meta:
		description = "Trojan:Win32/Falstart.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 61 63 65 62 6f 6f 6b 20 68 61 63 6b 20 56 } //1 facebook hack V
		$a_01_1 = {2a 20 20 20 50 20 20 61 20 20 73 20 20 73 20 20 77 20 20 6f 20 20 72 20 20 64 20 20 2a } //1 *   P  a  s  s  w  o  r  d  *
		$a_01_2 = {56 69 63 74 69 6d 27 73 20 45 2d 4d 61 69 6c } //1 Victim's E-Mail
		$a_01_3 = {42 79 20 3a 20 4d 72 2e 4a 75 42 61 20 20 61 6e 64 20 20 44 2e 4d 65 74 61 } //1 By : Mr.JuBa  and  D.Meta
		$a_01_4 = {72 00 65 00 61 00 64 00 20 00 6d 00 65 00 2e 00 65 00 78 00 65 00 } //1 read me.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}