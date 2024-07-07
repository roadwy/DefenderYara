
rule Trojan_Win32_Emotet_CV{
	meta:
		description = "Trojan:Win32/Emotet.CV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {59 41 63 74 69 76 65 58 61 6e 64 65 72 47 68 47 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 42 } //1 YActiveXanderGhGinstallationB
		$a_01_1 = {49 6e 74 65 72 6e 65 74 69 69 6e 73 74 61 6e 63 65 62 65 65 6e 43 43 2e } //1 InternetiinstancebeenCC.
		$a_00_2 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 } //1 Microsoft Corporatio
		$a_00_3 = {44 00 65 00 6d 00 6f 00 53 00 68 00 69 00 65 00 6c 00 64 00 20 00 44 00 65 00 73 00 69 00 67 00 6e 00 65 00 72 00 40 00 41 00 20 00 6d 00 61 00 63 00 72 00 6f 00 20 00 69 00 73 00 20 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 6c 00 79 00 20 00 62 00 65 00 69 00 6e 00 67 00 20 00 72 00 65 00 63 00 6f 00 72 00 64 00 65 00 64 00 } //1 DemoShield Designer@A macro is currently being recorded
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}