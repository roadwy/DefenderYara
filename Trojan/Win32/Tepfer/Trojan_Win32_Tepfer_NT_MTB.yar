
rule Trojan_Win32_Tepfer_NT_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {88 5d e7 ff 75 90 01 01 e8 1d fe ff ff 59 e8 0d 07 00 00 8b f0 33 ff 39 3e 74 1b 56 e8 75 fd ff ff 59 84 c0 90 00 } //01 00 
		$a_01_1 = {41 70 70 50 6f 6c 69 63 79 47 65 74 50 72 6f 63 65 73 73 54 65 72 6d 69 6e 61 74 69 6f 6e 4d 65 74 68 6f 64 } //00 00  AppPolicyGetProcessTerminationMethod
	condition:
		any of ($a_*)
 
}