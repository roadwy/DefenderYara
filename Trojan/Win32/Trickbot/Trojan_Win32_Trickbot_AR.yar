
rule Trojan_Win32_Trickbot_AR{
	meta:
		description = "Trojan:Win32/Trickbot.AR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 55 73 65 72 73 5c 55 73 65 72 5c 44 65 73 6b 74 6f 70 5c 63 6f 6d 6d 61 70 5c 63 74 6c 63 6f 6d 6d 5c 52 65 6c 65 61 73 65 5c 63 74 6c 63 6f 6d 6d 2e 70 64 62 } //1 c:\Users\User\Desktop\commap\ctlcomm\Release\ctlcomm.pdb
	condition:
		((#a_01_0  & 1)*1) >=1
 
}