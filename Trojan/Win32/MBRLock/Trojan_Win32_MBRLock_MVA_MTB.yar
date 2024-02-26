
rule Trojan_Win32_MBRLock_MVA_MTB{
	meta:
		description = "Trojan:Win32/MBRLock.MVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {59 6f 75 72 20 64 69 73 6b 20 68 61 76 65 20 61 20 6c 6f 63 6b } //02 00  Your disk have a lock
		$a_00_1 = {70 68 79 73 69 63 61 6c 64 72 69 76 65 30 } //01 00  physicaldrive0
		$a_80_2 = {65 79 75 79 61 6e } //eyuyan  01 00 
		$a_00_3 = {6c 2e 63 68 73 5c 61 66 78 72 65 73 2e 72 63 } //00 00  l.chs\afxres.rc
	condition:
		any of ($a_*)
 
}