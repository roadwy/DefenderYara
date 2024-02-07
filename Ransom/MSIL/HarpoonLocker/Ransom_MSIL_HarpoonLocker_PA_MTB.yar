
rule Ransom_MSIL_HarpoonLocker_PA_MTB{
	meta:
		description = "Ransom:MSIL/HarpoonLocker.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 72 00 65 00 73 00 74 00 6f 00 72 00 65 00 2d 00 66 00 69 00 6c 00 65 00 73 00 2e 00 74 00 78 00 74 00 } //01 00  \restore-files.txt
		$a_01_1 = {2e 00 6c 00 6f 00 63 00 6b 00 65 00 64 00 } //01 00  .locked
		$a_01_2 = {62 00 63 00 64 00 65 00 64 00 69 00 74 00 20 00 2f 00 64 00 65 00 6c 00 65 00 74 00 65 00 76 00 61 00 6c 00 75 00 65 00 20 00 7b 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 7d 00 20 00 73 00 61 00 66 00 65 00 62 00 6f 00 6f 00 74 00 } //01 00  bcdedit /deletevalue {current} safeboot
		$a_01_3 = {73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 20 00 2f 00 72 00 20 00 2f 00 74 00 20 00 30 00 } //00 00  shutdown /r /t 0
	condition:
		any of ($a_*)
 
}