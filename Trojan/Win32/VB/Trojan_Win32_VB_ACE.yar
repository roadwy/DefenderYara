
rule Trojan_Win32_VB_ACE{
	meta:
		description = "Trojan:Win32/VB.ACE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 00 68 00 65 00 6e 00 6a 00 69 00 6e 00 67 00 79 00 75 00 61 00 6e 00 69 00 65 00 35 00 32 00 30 00 } //1 shenjingyuanie520
		$a_03_1 = {53 00 74 00 61 00 74 00 2e 00 61 00 73 00 68 00 78 00 3f 00 4d 00 61 00 63 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? 26 00 48 00 61 00 72 00 64 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? 26 00 43 00 6c 00 69 00 65 00 6e 00 74 00 54 00 79 00 70 00 65 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? 26 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 3d 00 ?? ?? ?? ?? ?? ?? 26 00 55 00 73 00 65 00 72 00 49 00 44 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? 26 00 41 00 75 00 74 00 68 00 65 00 6e 00 3d 00 } //1
		$a_01_2 = {48 00 41 00 48 00 40 00 4b 00 47 00 4f 00 49 00 40 00 4f 00 45 00 4d 00 40 00 46 00 49 00 4b 00 44 00 42 00 49 00 4a 00 46 00 49 00 43 00 46 00 4c 00 41 00 4f 00 48 00 4d 00 4b 00 48 00 4c 00 49 00 4d 00 40 00 46 00 42 00 4a 00 4c 00 45 00 47 00 47 00 41 00 4c 00 48 00 44 00 47 00 47 00 47 00 47 00 46 00 4a 00 40 00 4f 00 48 00 4d 00 4f 00 48 00 50 00 42 00 44 00 4f 00 4a 00 47 00 43 00 45 00 4d 00 4f 00 4b 00 44 00 47 00 42 00 4d 00 41 00 4c 00 41 00 44 00 42 00 4a 00 47 00 4c 00 40 00 4e 00 4b 00 44 00 43 00 50 00 42 00 40 00 45 00 47 00 44 00 49 00 49 00 4b 00 47 00 42 00 49 00 40 00 } //1 HAH@KGOI@OEM@FIKDBIJFICFLAOHMKHLIM@FBJLEGGALHDGGGGFJ@OHMOHPBDOJGCEMOKDGBMALADBJGL@NKDCPB@EGDIIKGBI@
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}