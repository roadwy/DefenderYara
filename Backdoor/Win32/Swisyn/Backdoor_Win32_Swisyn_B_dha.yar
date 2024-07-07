
rule Backdoor_Win32_Swisyn_B_dha{
	meta:
		description = "Backdoor:Win32/Swisyn.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {52 65 63 76 20 25 35 64 20 62 79 74 65 73 20 66 72 6f 6d 20 25 73 3a 25 64 } //1 Recv %5d bytes from %s:%d
		$a_01_1 = {5b 53 45 52 56 45 52 5d 63 6f 6e 6e 65 63 74 69 6f 6e 20 74 6f 20 25 73 3a 25 64 20 65 72 72 6f 72 } //1 [SERVER]connection to %s:%d error
		$a_01_2 = {21 53 54 4f 50 4b 45 59 4c 4f 47 00 } //1 匡佔䭐奅佌G
		$a_01_3 = {53 54 4f 50 50 4f 52 54 4d 41 50 20 50 6f 72 74 4d 61 70 20 45 6e 64 21 2e } //1 STOPPORTMAP PortMap End!.
		$a_01_4 = {21 50 52 4f 58 59 49 4e 46 4f } //1 !PROXYINFO
		$a_01_5 = {2d 73 6c 61 76 65 00 } //1
		$a_01_6 = {2d 74 72 61 6e 00 } //1 琭慲n
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}