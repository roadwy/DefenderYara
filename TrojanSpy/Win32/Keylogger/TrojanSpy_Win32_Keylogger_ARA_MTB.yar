
rule TrojanSpy_Win32_Keylogger_ARA_MTB{
	meta:
		description = "TrojanSpy:Win32/Keylogger.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {3a 5c 54 45 4d 50 5c 4b 65 79 4c 6f 67 2e 74 78 74 } //2 :\TEMP\KeyLog.txt
		$a_01_1 = {5c 4d 6d 4e 65 77 2e 70 64 62 } //2 \MmNew.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}