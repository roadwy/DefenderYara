
rule Trojan_Win32_CryptInject_AE_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 30 35 5c 50 72 6f 6a 65 63 74 73 5c 42 6f 6d 62 65 72 32 5c 72 65 6c 65 61 73 65 5c 42 6f 6d 62 65 72 32 2e 70 64 62 } //00 00  Administrator\Documents\Visual Studio 2005\Projects\Bomber2\release\Bomber2.pdb
	condition:
		any of ($a_*)
 
}