
rule Trojan_Win32_Razy_ARA_MTB{
	meta:
		description = "Trojan:Win32/Razy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_80_0 = {5c 43 75 6d 20 34 20 53 6c 75 74 73 2e 6c 6e 6b } //\Cum 4 Sluts.lnk  02 00 
		$a_01_1 = {5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 43 75 6d 20 34 20 53 6c 75 74 73 2d 75 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //00 00  \WINDOWS\SYSTEM32\Cum 4 Sluts-uninstall.exe
	condition:
		any of ($a_*)
 
}