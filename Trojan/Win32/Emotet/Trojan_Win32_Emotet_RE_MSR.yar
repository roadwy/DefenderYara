
rule Trojan_Win32_Emotet_RE_MSR{
	meta:
		description = "Trojan:Win32/Emotet.RE!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 4d 79 20 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 50 72 6f 6a 65 63 74 73 5c 45 41 53 5a 5a 43 44 46 52 5c 52 65 6c 65 61 73 65 5c 45 41 53 5a 5a 43 44 46 52 2e 70 64 62 } //2 c:\Documents and Settings\Administrator\My Documents\Visual Studio Projects\EASZZCDFR\Release\EASZZCDFR.pdb
	condition:
		((#a_01_0  & 1)*2) >=2
 
}