
rule Trojan_BAT_Injector_RC_MSR{
	meta:
		description = "Trojan:BAT/Injector.RC!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 4a 61 6d 69 65 5c 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 30 38 5c 50 72 6f 6a 65 63 74 73 5c 57 69 6e 64 6f 77 73 41 70 70 6c 69 63 61 74 69 6f 6e 31 35 5c 57 69 6e 64 6f 77 73 41 70 70 6c 69 63 61 74 69 6f 6e 31 35 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 57 69 6e 64 6f 77 73 41 70 70 6c 69 63 61 74 69 6f 6e 31 35 2e 70 64 62 } //5 C:\Users\Jamie\Documents\Visual Studio 2008\Projects\WindowsApplication15\WindowsApplication15\obj\Release\WindowsApplication15.pdb
		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //5 WriteProcessMemory
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}