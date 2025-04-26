
rule Trojan_Win32_Emotet_SG_MSR{
	meta:
		description = "Trojan:Win32/Emotet.SG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 55 73 65 72 73 5c 55 73 65 72 5c 44 65 73 6b 74 6f 70 5c 32 30 30 38 5c 54 72 61 63 6b 65 72 5c 52 65 6c 65 61 73 65 5c 54 72 61 63 6b 65 72 2e 70 64 62 } //1 \Users\User\Desktop\2008\Tracker\Release\Tracker.pdb
		$a_01_1 = {4c 6f 63 6b 46 69 6c 65 } //1 LockFile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}