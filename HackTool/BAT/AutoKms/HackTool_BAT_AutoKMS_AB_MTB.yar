
rule HackTool_BAT_AutoKMS_AB_MTB{
	meta:
		description = "HackTool:BAT/AutoKMS.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {49 73 4b 6d 73 43 6c 69 65 6e 74 } //IsKmsClient  01 00 
		$a_80_1 = {4b 4d 53 45 4c 44 49 2e 70 64 62 } //KMSELDI.pdb  01 00 
		$a_80_2 = {41 63 74 69 76 61 74 69 6f 6e 20 47 55 49 20 66 6f 72 20 4b 4d 53 20 48 6f 73 74 } //Activation GUI for KMS Host  01 00 
		$a_80_3 = {73 65 74 5f 41 63 74 69 76 61 74 65 42 75 74 74 6f 6e } //set_ActivateButton  01 00 
		$a_80_4 = {52 75 6e 20 4b 4d 53 20 45 6d 75 6c 61 74 6f 72 } //Run KMS Emulator  01 00 
		$a_80_5 = {57 69 6e 64 6f 77 73 20 41 63 74 69 76 61 74 65 64 } //Windows Activated  00 00 
	condition:
		any of ($a_*)
 
}