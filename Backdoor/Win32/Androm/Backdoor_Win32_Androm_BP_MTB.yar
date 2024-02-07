
rule Backdoor_Win32_Androm_BP_MTB{
	meta:
		description = "Backdoor:Win32/Androm.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {41 66 66 61 6c 64 73 73 6b 61 6b 74 65 6e 5c 70 72 65 73 73 65 66 6f 6c 64 5c 64 75 65 6c 62 65 6e 65 } //02 00  Affaldsskakten\pressefold\duelbene
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 42 6f 63 68 75 72 5c 4d 61 6c 69 63 65 70 72 6f 6f 66 5c 44 65 73 75 6c 66 75 72 69 73 61 74 69 6f 6e 5c 61 75 74 6f 6d 61 74 69 7a 61 74 69 6f 6e 73 } //01 00  Software\Microsoft\Windows\CurrentVersion\Uninstall\Bochur\Maliceproof\Desulfurisation\automatizations
		$a_01_2 = {5b 52 65 6e 61 6d 65 5d } //00 00  [Rename]
	condition:
		any of ($a_*)
 
}